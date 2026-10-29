"""Offline fault injection for the official single-file lineage retry contract."""
import copy
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import knowledge_gate as kb


FID='9bf08385-0e18-43c4-9df8-3051e61ad112'
OLD='3ccd6858-3ee8-535a-b557-c6d6557de622'
NEW='43d2102f-5b74-58e2-9235-946e313dbb39'
DISPATCH='5c72801d-267b-448e-8d1b-1f87ee245710'
RETRY_DISPATCH='6336f783-e2b3-42ad-bfc4-a0b769644e89'
FAILURE_REQUEST='498e8ef8-06f2-4f19-8c5b-f85e13bf1dda'
LINEAGE=f'[moi:data.lineage.register] register lineage for source_file_id {FID}: [1] Internal Server Error (request_id: {FAILURE_REQUEST})'
ARTIFACTS=[dict(file_id=FID,name='original.md')]


class Crash(BaseException):
    pass


class Clock:
    def __init__(self):self.epoch=1000;self.mono=0
    def advance(self,seconds):self.epoch+=seconds;self.mono+=seconds


class Journal:
    def __init__(self,value):self.value=value;self.persisted=copy.deepcopy(value);self.hook=None
    def save(self):
        if self.hook:self.hook(self)
        self.persisted=copy.deepcopy(self.value)


class Job:
    def __init__(self,api,state=None):
        self.api=api
        self.state=copy.deepcopy(state) if state is not None else dict(prefix='receipts/20261028/same-batch')
        self.journal=Journal(self.state);self.stored={}
    def store(self,name,value):self.stored[name]=copy.deepcopy(value);return dict(key=name)


class FakeAPI:
    """No transport exists. Unexpected routes and all other mutations fail."""
    def __init__(self):
        self.calls=[];self.posts=[];self.commits=0;self.post_fault=None
        self.registered=True;self.source_status='failed';self.source_error=f'workflow execution {DISPATCH} not found: domain object not found'
        self.old=dict(execution_id=OLD,workflow_id=kb.KB_WORKFLOW_ID,status='failed',
                      execution_mode='volume_trigger',error=LINEAGE)
        self.new=dict(execution_id=NEW,workflow_id=kb.KB_WORKFLOW_ID,status='completed',execution_mode='volume_trigger')
        self.original_list=dict(self.old,file_id=FID,dispatch_job_id=DISPATCH)
        self.retry_list=dict(self.new,file_id=FID,dispatch_job_id=RETRY_DISPATCH)
        self.extra=[];self.list_prefix=[];self.response=None;self.hide_new=False;self.disappear=False
        self.read_fault=None;self.on_list=None
    @staticmethod
    def data(value):return value
    def request(self,path,payload=None,method=None,timeout=None,retry=True):
        self.calls.append((path,copy.deepcopy(payload),method))
        route=urlsplit(path);query=parse_qs(route.query)
        if payload is not None:
            assert route.path==kb.WORKFLOWS+'/'+kb.KB_WORKFLOW_ID+'/executions/batch-retry',path
            assert method=='POST'
            self.posts.append(copy.deepcopy(payload))
            assert payload==dict(source_dispatch_job_id=DISPATCH,execution_ids=[OLD],all_failed=False,
                                 request_id=kb.lineage_request_id(self.job,FID,OLD))
            assert self.job.journal.persisted['knowledge_registration'][FID]['lineage_recovery']['request']==payload
            if self.post_fault=='before_accept':raise TimeoutError()
            if self.post_fault=='unknown':raise ValueError('unknown_server_error')
            self.commits+=1
            if self.post_fault=='after_accept':raise TimeoutError()
            if self.post_fault=='crash_after_accept':raise Crash()
            return self.response or dict(source_dispatch_job_id=DISPATCH,dispatch_job_id=RETRY_DISPATCH,
                                         accepted_count=1,status='waiting',replayed=False)
        assert method in (None,'GET')
        if self.read_fault:
            fault=self.read_fault;self.read_fault=None;raise fault
        if route.path=='/semantic-models/80001/sources':
            if not self.registered or (self.disappear and self.posts):return dict(items=[])
            status='succeeded' if self.commits and not self.hide_new else self.source_status
            return dict(items=[dict(source_id='original-source',source_file_id=FID,kb_file_id=FID,
                                   ingest_status=status,error=self.source_error)])
        if route.path=='/semantic-models/80001/source-jobs':return dict(items=[],reconcile_required=True)
        if route.path==kb.WORKFLOWS+'/file-executions':
            assert query==dict(file_id=[FID])
            values=([self.new] if self.commits and not self.hide_new else [])+self.extra+[self.old]
            return dict(executions=copy.deepcopy(values),total=len(values))
        if route.path==kb.WORKFLOWS+'/'+kb.KB_WORKFLOW_ID+'/executions':
            if self.on_list:self.on_list()
            values=self.list_prefix+([self.retry_list] if self.commits and not self.hide_new else [])+[self.original_list]
            offset=int(query['offset'][0]);limit=int(query['limit'][0]);assert limit==10
            return dict(executions=copy.deepcopy(values[offset:offset+limit]),total=len(values))
        raise AssertionError(path)


class KnowledgeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(kb.time,'time',side_effect=lambda:self.clock.epoch))
        self.stack.enter_context(patch.object(kb.time,'monotonic',side_effect=lambda:self.clock.mono))
        self.stack.enter_context(patch.object(kb.time,'sleep',side_effect=self.clock.advance))
        self.stack.enter_context(patch.object(kb,'emit'))
        self.stack.enter_context(patch('pipeline_telemetry.emit'))
        self.stack.enter_context(patch('socket.socket',side_effect=AssertionError('network forbidden')))
        # A fake must explicitly request reconcile to test that a recovery skips
        # it. Suppress the old generic reconcile path in non-recovery cases.
        self.api=FakeAPI();self.job=Job(self.api);self.api.job=self.job
    def run_gate(self,**kwargs):
        return kb.ensure_sources(self.job,ARTIFACTS,poll_seconds=1,deadline_seconds=10,**kwargs)
    def restart(self):
        self.job=Job(self.api,self.job.journal.persisted);self.api.job=self.job
    def state(self):return self.job.state['knowledge_registration'][FID]
    def no_reconcile(self):
        request=self.api.request
        def wrapped(path,*args,**kwargs):
            value=request(path,*args,**kwargs)
            if path.endswith('/source-jobs'):value['reconcile_required']=False
            return value
        self.stack.enter_context(patch.object(self.api,'request',side_effect=wrapped))
    def test_exact_failed_lineage_uses_official_contract_and_retains_both_executions(self):
        self.run_gate()
        recovery=self.state()['lineage_recovery']
        self.assertEqual((len(self.api.posts),self.api.commits),(1,1))
        self.assertEqual(recovery['original_execution'],self.api.old)
        self.assertEqual(recovery['new_execution'],self.api.new)
        self.assertEqual(recovery['failure_request_id'],FAILURE_REQUEST)
        self.assertEqual(recovery['new_dispatch_job_id'],RETRY_DISPATCH)
        self.assertEqual(recovery['correlation'],'acknowledged_dispatch')
        self.assertEqual(recovery['request_id'],self.api.posts[0]['request_id'])
        self.assertEqual(recovery['attempts'],1)
        self.assertTrue(self.state()['succeeded'])
        self.assertEqual(next(iter(self.job.stored.values()))[0]['source_id'],'original-source')
    def test_timeout_after_server_commit_only_observes_original_file(self):
        self.api.post_fault='after_accept';self.run_gate()
        recovery=self.state()['lineage_recovery']
        self.assertEqual((len(self.api.posts),self.api.commits),(1,1))
        self.assertEqual(recovery['status'],'submission_unknown')
        self.assertEqual(recovery['new_execution']['execution_id'],NEW)
        self.assertEqual(recovery['correlation'],'same_file_observation')
    def test_timeout_before_server_accept_is_consumed_and_not_replayed_on_resume(self):
        self.api.post_fault='before_accept'
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        recovery=copy.deepcopy(self.state()['lineage_recovery']);deadline=self.state()['ingestion_deadline_epoch']
        self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual((len(self.api.posts),self.api.commits),(1,0))
        self.assertEqual(self.state()['lineage_recovery'],recovery)
        self.assertEqual(self.state()['ingestion_deadline_epoch'],deadline)
    def test_checkpoint_timeout_before_post_never_submits_even_when_put_committed(self):
        def fail(journal):
            if journal.value['knowledge_registration'][FID].get('lineage_recovery'):
                journal.persisted=copy.deepcopy(journal.value);raise TimeoutError()
        self.job.journal.hook=fail
        with self.assertRaisesRegex(ValueError,'checkpoint_unconfirmed'):self.run_gate()
        self.assertEqual(self.api.posts,[])
        self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_crash_after_reservation_before_post_does_not_submit_on_resume(self):
        def crash(journal):
            if journal.value['knowledge_registration'][FID].get('lineage_recovery'):
                journal.persisted=copy.deepcopy(journal.value);raise Crash()
        self.job.journal.hook=crash
        with self.assertRaises(Crash):self.run_gate()
        rid=self.state()['lineage_recovery']['request_id'];self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
        self.assertEqual(self.state()['lineage_recovery']['request_id'],rid)
    def test_crash_after_commit_reuses_same_checkpoint_and_never_second_post(self):
        self.api.post_fault='crash_after_accept'
        with self.assertRaises(Crash):self.run_gate()
        request=copy.deepcopy(self.api.posts[0]);self.restart();self.run_gate()
        self.assertEqual(self.api.posts,[request])
        self.assertEqual(self.state()['lineage_recovery']['new_execution']['execution_id'],NEW)
    def test_crash_before_acceptance_checkpoint_does_not_replay(self):
        def fail(journal):
            recovery=journal.value['knowledge_registration'][FID].get('lineage_recovery',{})
            if recovery.get('status')=='accepted':raise Crash()
        self.job.journal.hook=fail
        with self.assertRaises(Crash):self.run_gate()
        self.assertEqual(self.job.journal.persisted['knowledge_registration'][FID]['lineage_recovery']['status'],'submission_unknown')
        self.restart();self.run_gate();self.assertEqual(len(self.api.posts),1)
    def test_acceptance_checkpoint_timeout_does_not_replay(self):
        failures=[]
        def fail(journal):
            recovery=journal.value['knowledge_registration'][FID].get('lineage_recovery',{})
            if recovery.get('status')=='accepted' and not failures:
                failures.append(True);raise TimeoutError()
        self.job.journal.hook=fail;self.run_gate()
        self.assertEqual(len(self.api.posts),1);self.assertTrue(failures)
    def test_dispatch_lookup_uses_official_offset_pagination(self):
        self.api.list_prefix=[dict(execution_id='unrelated-'+str(i)) for i in range(10)]
        self.run_gate()
        offsets=[parse_qs(urlsplit(path).query)['offset'][0] for path,_,_ in self.api.calls
                 if urlsplit(path).path==kb.WORKFLOWS+'/'+kb.KB_WORKFLOW_ID+'/executions']
        self.assertEqual(offsets,['0','10','0','10'])
    def test_pending_execution_prevents_retry_of_older_failed_lineage(self):
        self.no_reconcile();self.api.extra=[dict(self.api.new,status='pending')]
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_pending_source_never_retries_even_with_failed_file_execution(self):
        self.no_reconcile();self.api.source_status='pending'
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_non_lineage_unknown_error_or_another_fid_blocks(self):
        for error in ['embedding failed',LINEAGE.replace('lineage.register','lineage.read'),
                      LINEAGE.replace('Internal Server Error','Forbidden'),
                      LINEAGE.replace(FID,'another-file'),LINEAGE+' extra']:
            with self.subTest(error=error):
                self.api.old['error']=error
                with self.assertRaisesRegex(ValueError,'requires_backend_repair'):self.run_gate()
                self.assertEqual(self.api.posts,[])
    def test_non_failed_terminal_execution_is_not_retryable(self):
        for status in ('cancelled','unknown'):
            with self.subTest(status=status):
                self.api.old['status']=status
                with self.assertRaisesRegex(ValueError,'requires_backend_repair'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_exact_file_execution_query_does_not_authorize_another_workflow(self):
        self.api.old['workflow_id']='other-workflow'
        with self.assertRaisesRegex(ValueError,'requires_backend_repair'):self.run_gate(runtime_visibility_grace_seconds=0)
        self.assertEqual(self.api.posts,[])
    def test_list_correlation_requires_same_fid_workflow_execution_status_and_error(self):
        for key,value in [('file_id','another-file'),('workflow_id','other-workflow'),
                          ('execution_id','another-execution'),('status','running'),
                          ('error','embedding failed'),('dispatch_job_id','')]:
            with self.subTest(key=key):
                self.api.original_list=dict(self.api.old,file_id=FID,dispatch_job_id=DISPATCH)
                self.api.original_list[key]=value
                with self.assertRaisesRegex(ValueError,'identity_mismatch|dispatch_unavailable'):self.run_gate()
                self.assertEqual(self.api.posts,[])
    def test_explicit_wrong_file_id_in_file_facts_blocks(self):
        self.api.old['file_id']='another-file'
        with self.assertRaisesRegex(ValueError,'identity_mismatch'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_conflicting_source_file_and_kb_file_alias_cannot_authorize_retry(self):
        source=dict(source_id='other-source',source_file_id='another-file',kb_file_id=FID,
                    ingest_status='failed',error=LINEAGE)
        with patch.object(kb,'rows',return_value=[source]):
            with self.assertRaisesRegex(ValueError,'source_identity_mismatch'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_unknown_post_error_is_persistently_blocked(self):
        self.api.post_fault='unknown'
        with self.assertRaisesRegex(ValueError,'retry_rejected'):self.run_gate()
        self.restart()
        with self.assertRaisesRegex(ValueError,'retry_blocked'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
    def test_invalid_acknowledgement_blocks_without_second_submission(self):
        self.api.hide_new=True
        self.api.response=dict(source_dispatch_job_id=DISPATCH,dispatch_job_id=RETRY_DISPATCH,
                               accepted_count=2,status='waiting',replayed=False)
        with self.assertRaisesRegex(ValueError,'response_invalid'):self.run_gate()
        self.restart()
        with self.assertRaisesRegex(ValueError,'retry_blocked'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
    def test_retry_failure_cannot_refresh_attempt_count_or_deadline(self):
        self.api.new.update(status='failed',error=LINEAGE)
        self.api.retry_list.update(status='failed',error=LINEAGE)
        self.api.disappear=True
        with self.assertRaisesRegex(ValueError,'retry_exhausted'):self.run_gate()
        deadline=self.state()['ingestion_deadline_epoch'];self.restart()
        with self.assertRaisesRegex(ValueError,'retry_exhausted'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
        self.assertEqual(self.state()['lineage_recovery']['attempts'],1)
        self.assertEqual(self.state()['ingestion_deadline_epoch'],deadline)
    def test_observed_source_disappearing_after_unknown_submission_never_creates_copy(self):
        self.api.post_fault='before_accept';self.api.disappear=True
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate(registration_volume_id=140002)
        self.assertEqual(len(self.api.posts),1)
        self.assertNotIn('append_attempted',self.state())
        self.assertNotIn('selection_recovery_attempted',self.state())
    def test_previously_observed_source_missing_now_uses_original_file_facts(self):
        self.job.state['knowledge_registration']={FID:dict(observed=True)}
        self.api.registered=False
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
        self.assertEqual(self.state()['lineage_recovery']['new_execution']['execution_id'],NEW)
        self.assertNotIn('append_attempted',self.state())
    def test_resume_retains_budget_even_before_any_retry_and_after_read_timeout(self):
        self.no_reconcile();self.api.source_status='pending'
        self.api.read_fault=TimeoutError()
        def crash_sleep(seconds):self.clock.advance(seconds);raise Crash()
        with patch.object(kb.time,'sleep',side_effect=crash_sleep):
            with self.assertRaises(Crash):self.run_gate()
        deadline=self.state()['ingestion_deadline_epoch'];self.clock.advance(20);self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.state()['ingestion_deadline_epoch'],deadline)
        self.assertEqual(self.api.posts,[])
    def test_continuous_inventory_timeouts_cannot_refresh_expired_budget_on_resume(self):
        self.job.state['knowledge_registration']={FID:dict(ingestion_deadline_epoch=self.clock.epoch+2)}
        self.job.journal.save()
        with patch.object(kb,'rows',side_effect=TimeoutError()) as read:
            with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
            self.assertEqual(read.call_count,3)
            self.restart();before=self.clock.epoch
            with self.assertRaisesRegex(ValueError,'ingestion_deadline'):
                kb.ensure_sources(self.job,ARTIFACTS,poll_seconds=1,deadline_seconds=1800)
            self.assertEqual(self.clock.epoch,before)
            self.assertEqual(read.call_count,4)
        self.assertEqual(self.api.posts,[])
    def test_budget_is_durable_before_first_read_even_if_checkpoint_ack_is_lost(self):
        def fail(journal):journal.persisted=copy.deepcopy(journal.value);raise TimeoutError()
        self.job.journal.hook=fail
        with self.assertRaises(TimeoutError):self.run_gate()
        self.assertEqual(self.api.calls,[])
        deadline=self.state()['ingestion_deadline_epoch'];self.clock.advance(11);self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.state()['ingestion_deadline_epoch'],deadline)
    def test_deadline_expiring_during_fact_reads_or_checkpoint_prevents_post(self):
        for stage in ('list','checkpoint'):
            with self.subTest(stage=stage):
                self.api=FakeAPI();self.job=Job(self.api);self.api.job=self.job
                if stage=='list':self.api.on_list=lambda:self.clock.advance(11)
                else:
                    def expire(journal):
                        if journal.value['knowledge_registration'][FID].get('lineage_recovery'):self.clock.advance(11)
                    self.job.journal.hook=expire
                with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
                self.assertEqual(self.api.posts,[])
    def test_historical_succeeded_source_returns_before_expired_deadline(self):
        self.api.source_status='succeeded'
        self.job.state['knowledge_registration']={FID:dict(ingestion_deadline_epoch=1,succeeded=True)}
        self.run_gate()
        self.assertEqual(len(self.api.calls),1)
        self.assertTrue(self.state()['succeeded'])
    def test_historical_succeeded_source_after_retry_stays_accepted_past_deadline(self):
        self.run_gate();self.clock.advance(1801);self.restart();self.api.calls=[];self.run_gate()
        self.assertEqual(len(self.api.calls),1)
        self.assertEqual(len(self.api.posts),1)
    def test_successful_execution_alone_never_replaces_source_success_gate(self):
        self.no_reconcile();self.api.old['status']='completed'
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertNotIn('succeeded',self.state());self.assertEqual(self.api.posts,[])
    def test_missing_projection_without_official_facts_remains_bounded_and_blocked(self):
        self.no_reconcile()
        with patch.object(kb,'execution_facts',return_value=[]):
            with self.assertRaisesRegex(ValueError,'requires_backend_repair'):
                self.run_gate(runtime_visibility_grace_seconds=2)
        self.assertEqual(self.api.posts,[])
    def test_changed_batch_prefix_cannot_reuse_request_identity(self):
        self.api.post_fault='crash_after_accept'
        with self.assertRaises(Crash):self.run_gate()
        self.api.hide_new=True;self.restart();self.job.state['prefix']='another-batch'
        with self.assertRaisesRegex(ValueError,'checkpoint_identity_mismatch'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)


if __name__=='__main__':unittest.main()
