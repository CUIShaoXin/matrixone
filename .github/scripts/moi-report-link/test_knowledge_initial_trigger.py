"""Fault injection for original-file first processing and lost acknowledgements."""
import copy,hashlib,types,unittest
from unittest.mock import patch
import knowledge_initial_trigger as initial
import knowledge_gate as gate

FID='original-file';SID='original-source';VERSION='original-version'
RAW=b'MATRIX-READINESS-ORIGINAL';DIGEST=hashlib.sha256(RAW).hexdigest()
class Crash(BaseException):pass
class InitialTriggerTests(unittest.TestCase):
    def setUp(self):
        self.now=1000;self.saved=[];self.remote={};self.posts=[];self.facts=[];self.fail=None;self.mount=True
        self.response={'triggered':1};self.definition=dict(id=gate.KB_WORKFLOW_ID,status='ready',execution_mode='volume_trigger',latest_workflow_version_id=VERSION,trigger_summary=dict(mode='volume_trigger',configured=True,enabled=True,volume_id=140002),execution_summary=dict(active_executions=0))
        self.artifact=dict(file_id=FID,bytes=len(RAW),sha256=DIGEST)
        self.target=dict(file_id=FID,marker=RAW.decode())
        self.found=[dict(source_id=SID,source_file_id=FID,kb_file_id=FID,ingest_status='pending',error=None)]
        self.state=dict(ingestion_started_epoch=800,ingestion_deadline_epoch=2000,initial_no_execution_first_observed_epoch=900)
        self.job=types.SimpleNamespace(state={},api=types.SimpleNamespace(request=self.request,data=lambda v:v,file=lambda fid:RAW),objects=object())
        self.job.journal=types.SimpleNamespace(save=self.save)
        self.addCleanup(patch.stopall)
        patch('socket.socket',side_effect=AssertionError('network forbidden')).start()
        patch.object(initial.time,'time',side_effect=lambda:self.now).start()
        patch.object(initial,'emit').start()
        patch.object(gate,'execution_facts',side_effect=lambda *a:self.facts).start()
        patch.object(gate,'rows',side_effect=lambda *a:self.found).start()
        patch('daily_delivery.create_once',side_effect=self.create).start()
    def save(self):
        if self.fail=='save':raise TimeoutError()
        self.saved.append(copy.deepcopy(self.state))
    def create(self,objects,key,value):
        if key in self.remote:return False,copy.deepcopy(self.remote[key])
        self.remote[key]=copy.deepcopy(value)
        if self.fail=='reservation':raise TimeoutError()
        return True,copy.deepcopy(value)
    def request(self,path,payload=None,**kw):
        self.assertFalse(kw['retry'])
        if path=='/catalog/file/trigger_workflow':
            self.assertEqual(payload,dict(volume_id=140002,file_ids=[FID]))
            self.assertEqual(kw['method'],'POST')
            self.assertTrue(self.remote);self.assertEqual(self.saved[-1]['initial_trigger']['status'],'submission_unknown')
            self.posts.append(copy.deepcopy(payload))
            if self.fail=='post':raise TimeoutError()
            if self.fail=='crash':raise Crash()
            return self.response
        if path=='/catalog/file/list':return dict(list=[dict(file_id=FID)] if self.mount else [],total=1 if self.mount else 0)
        if path==gate.WORKFLOWS+'/'+gate.KB_WORKFLOW_ID:return dict(workflow=copy.deepcopy(self.definition))
        raise AssertionError(path)
    def run_recovery(self):return initial.recover(self.job,self.artifact,self.target,self.found,self.state,140002)
    def test_one_original_trigger_then_observation_only(self):
        self.assertTrue(self.run_recovery());self.assertTrue(self.run_recovery())
        self.assertEqual(len(self.posts),1);self.assertEqual(self.state['ingestion_deadline_epoch'],2000)
        self.assertEqual(self.state['initial_trigger']['status'],'acknowledged')
    def test_unknown_post_never_resubmitted_even_after_restart(self):
        self.fail='post';self.assertTrue(self.run_recovery());self.fail=None
        self.state=copy.deepcopy(self.saved[-1]);self.assertTrue(self.run_recovery());self.assertEqual(len(self.posts),1)
    def test_crash_after_post_recovers_remote_reservation_without_post(self):
        self.fail='crash'
        with self.assertRaises(Crash):self.run_recovery()
        self.state.pop('initial_trigger');self.fail=None
        self.assertTrue(self.run_recovery());self.assertEqual(len(self.posts),1)
    def test_reservation_lost_ack_no_post_or_repeat_after_restart(self):
        self.fail='reservation'
        with self.assertRaisesRegex(ValueError,'reservation_unconfirmed'):self.run_recovery()
        self.assertFalse(self.posts);self.fail=None;self.assertTrue(self.run_recovery());self.assertFalse(self.posts)
    def test_checkpoint_failure_after_reservation_sacrifices_post(self):
        self.fail='save'
        with self.assertRaisesRegex(ValueError,'checkpoint_unconfirmed'):self.run_recovery()
        self.assertFalse(self.posts);self.state.pop('initial_trigger');self.fail=None
        self.assertTrue(self.run_recovery());self.assertFalse(self.posts)
    def test_fresh_file_waits_120_seconds_and_two_empty_observations(self):
        self.state=dict(ingestion_started_epoch=1000,ingestion_deadline_epoch=1600)
        self.assertFalse(self.run_recovery());self.assertFalse(self.posts)
        self.now=1120;self.assertFalse(self.run_recovery())
        self.now=1149;self.assertFalse(self.run_recovery())
        self.now=1150;self.assertTrue(self.run_recovery());self.assertEqual(len(self.posts),1)
    def test_existing_legacy_budget_starts_observation_without_reset(self):
        self.state.pop('ingestion_started_epoch');self.assertFalse(self.run_recovery())
        self.assertEqual(self.state['ingestion_deadline_epoch'],2000);self.assertFalse(self.posts)
        self.now=1120;self.assertTrue(self.run_recovery())
    def test_existing_execution_of_any_status_is_not_first_processing(self):
        for status in ['running','completed','failed','pending','unknown']:
            self.facts=[dict(status=status)]
            self.assertFalse(self.run_recovery())
        self.assertFalse(self.posts)
    def test_source_error_duplicate_or_identity_never_authorizes(self):
        for change in [dict(ingest_status='failed'),dict(ingest_status='succeeded'),dict(error='unknown'),dict(kb_file_id='wrong'),dict(source_file_id='wrong')]:
            with self.subTest(change=change):
                self.found=[dict(source_id=SID,source_file_id=FID,kb_file_id=FID,ingest_status='pending',error=None,**{})];self.found[0].update(change)
                self.assertFalse(self.run_recovery())
        self.found=self.found*2;self.assertFalse(self.run_recovery());self.assertFalse(self.posts)
    def test_wrong_raw_hash_or_absent_mount_blocks(self):
        self.artifact['sha256']='wrong'
        with self.assertRaisesRegex(ValueError,'hash_mismatch'):self.run_recovery()
        self.artifact['sha256']=DIGEST;self.mount=False
        with self.assertRaisesRegex(ValueError,'not_mounted'):self.run_recovery()
        self.assertFalse(self.posts)
    def test_active_workflow_waits_without_reservation(self):
        self.definition['execution_summary']['active_executions']=1
        self.assertFalse(self.run_recovery());self.assertFalse(self.remote)
    def test_wrong_workflow_or_volume_configuration_blocks(self):
        self.definition['trigger_summary']['volume_id']=9
        with self.assertRaisesRegex(ValueError,'workflow_identity'):self.run_recovery()
        self.assertFalse(self.posts)
    def test_expired_original_deadline_blocks(self):
        self.now=2000
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_recovery()
        self.assertFalse(self.remote)
    def test_bad_trigger_response_is_terminal_without_repeat(self):
        self.response={'triggered':2}
        for i in range(2):
            with self.assertRaisesRegex(ValueError,'trigger_rejected'):self.run_recovery()
        self.assertEqual(len(self.posts),1)
    def test_another_journal_observes_same_global_reservation(self):
        self.assertTrue(self.run_recovery());self.state.pop('initial_trigger');self.assertTrue(self.run_recovery())
        self.assertEqual(len(self.posts),1)
    def test_conflicting_global_reservation_blocks(self):
        self.run_recovery();self.state.pop('initial_trigger')
        next(iter(self.remote.values()))['artifact_sha256']='wrong'
        with self.assertRaisesRegex(ValueError,'reservation_identity_mismatch'):self.run_recovery()
        self.assertEqual(len(self.posts),1)
    def test_existing_reserved_identity_cannot_be_rebound(self):
        self.run_recovery();self.state['initial_trigger']['file_id']='wrong'
        with self.assertRaisesRegex(ValueError,'checkpoint_identity_mismatch'):self.run_recovery()
        self.assertEqual(len(self.posts),1)
    def test_first_processing_reservation_cannot_hide_later_real_failure(self):
        self.run_recovery();self.found[0]['ingest_status']='failed'
        self.assertFalse(self.run_recovery());self.assertEqual(len(self.posts),1)
    def test_original_deadline_cannot_be_refreshed_after_reservation(self):
        self.run_recovery();self.state['ingestion_deadline_epoch']=3000
        with self.assertRaisesRegex(ValueError,'checkpoint_identity_mismatch'):self.run_recovery()
        self.assertEqual(len(self.posts),1)
if __name__=='__main__':unittest.main()
