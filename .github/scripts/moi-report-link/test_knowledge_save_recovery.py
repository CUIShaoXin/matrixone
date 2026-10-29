"""Fault injection: retain original identities and consume only one node POST."""
import copy
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from urllib.parse import urlsplit

import knowledge_gate as kb
from knowledge_save_recovery import recover_save_node, NODE
from test_knowledge_recovery import (Clock,Crash,Job,FakeAPI,FID,OLD,NEW,FAILURE_REQUEST,ARTIFACTS)

SINK=f'[moi:catalog.sink.write] [1] Internal Server Error (request_id: {FAILURE_REQUEST})'


class SaveAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.old['error']=SINK;self.original_list['error']=SINK
        self.source_error=SINK
        self.plan=dict(workflow_id=kb.KB_WORKFLOW_ID,source_execution_id=OLD,
                       source_case_id='case-old',source_branch_id='branch-old',node_key=NODE,
                       source_node_execution_id='node-old',rerun_contract_hash='sha256:'+'a'*64,
                       node_status='FAILED',available_modes=['continue_from_node'],validation={'ok':True},
                       affected_downstream_nodes=[dict(node_key='root.register_lineage',node_type='data.lineage.register')],
                       candidates=[dict(source_node_execution_id='node-old',status='FAILED',error=SINK)])
        self.input=dict(file_id=FID,volume_id=140002,sources=[dict(file_id=FID,name='original.md')])
        self.new_input=copy.deepcopy(self.input)
        self.branch=dict(rerun_id='rerun-1',branch_id='branch-new',case_id='case-new',
                         source_branch_id='branch-old',source_case_id='case-old',
                         source_execution_id=OLD,source_node_execution_id='node-old',node_key=NODE,
                         mode='rerun_current_and_downstream',new_workflow_execution_id=NEW,status='succeeded')
        self.prior=[];self.hide_branch=False;self.bad_ack=False

    def request(self,path,payload=None,method=None,timeout=None):
        route=kb.WORKFLOWS+'/'+kb.KB_WORKFLOW_ID+'/executions/'
        if path.startswith(route):
            self.calls.append((path,copy.deepcopy(payload),method))
            tail=path[len(route):]
            if payload is not None:
                assert tail==OLD+'/nodes/'+NODE+'/reruns' and method=='POST'
                self.posts.append(copy.deepcopy(payload))
                saved=self.job.journal.persisted['knowledge_registration'][FID]['save_node_recovery']
                assert saved['status']=='submission_unknown' and saved['request']==payload
                assert set(payload)=={'mode','source_node_execution_id','expected_rerun_contract_hash','reason'}
                if self.post_fault=='before_accept':raise TimeoutError()
                if self.post_fault=='unknown':raise ValueError('unknown')
                self.commits+=1
                if self.post_fault=='after_accept':raise TimeoutError()
                if self.post_fault=='crash_after_accept':raise Crash()
                return dict(rerun=dict(self.branch,source_execution_id='wrong') if self.bad_ack else self.branch)
            if tail==OLD:return dict(execution=dict(self.old,input_payload=self.input))
            if tail==NEW:return dict(execution=dict(self.new,input_payload=self.new_input))
            if tail==OLD+'/nodes/'+NODE+'/rerun-plan':return dict(plan=self.plan)
            if tail==OLD+'/rerun-branches':
                return dict(reruns=self.prior+([self.branch] if self.commits and not self.hide_branch else []))
            if tail==OLD+'/reruns/rerun-1':return dict(rerun=self.branch)
            raise AssertionError(path)
        return super().request(path,payload,method,timeout)


class SaveRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(kb.time,'time',side_effect=lambda:self.clock.epoch))
        self.stack.enter_context(patch.object(kb.time,'monotonic',side_effect=lambda:self.clock.mono))
        self.stack.enter_context(patch.object(kb.time,'sleep',side_effect=self.clock.advance))
        self.stack.enter_context(patch('pipeline_telemetry.emit'))
        self.stack.enter_context(patch('socket.socket',side_effect=AssertionError('network forbidden')))
        self.api=SaveAPI();self.job=Job(self.api);self.api.job=self.job
    def run_gate(self):return kb.ensure_sources(self.job,ARTIFACTS,poll_seconds=1,deadline_seconds=10)
    def restart(self):self.job=Job(self.api,self.job.journal.persisted);self.api.job=self.job
    def state(self):return self.job.state['knowledge_registration'][FID]
    def test_exact_failure_continues_original_node_and_requires_real_source(self):
        self.run_gate();r=self.state()['save_node_recovery']
        self.assertEqual((len(self.api.posts),self.api.commits),(1,1))
        self.assertEqual(r['original_execution']['execution_id'],OLD)
        self.assertEqual(r['new_execution']['execution_id'],NEW)
        self.assertEqual(r['original_input'],r['new_execution']['input_payload'])
        self.assertEqual(r['request']['mode'],'continue_from_node')
        self.assertTrue(r['source_succeeded']);self.assertTrue(self.state()['succeeded'])
    def test_timeout_after_accept_observes_original_rerun_without_second_post(self):
        self.api.post_fault='after_accept';self.run_gate();self.restart();self.run_gate()
        self.assertEqual((len(self.api.posts),self.api.commits),(1,1))
        self.assertEqual(self.state()['save_node_recovery']['status'],'submission_unknown')
        self.assertEqual(self.state()['save_node_recovery']['rerun']['rerun_id'],'rerun-1')
    def test_timeout_before_accept_is_not_replayed_and_cannot_refresh_clock(self):
        self.api.post_fault='before_accept'
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        deadline=self.state()['ingestion_deadline_epoch'];self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual((len(self.api.posts),self.api.commits),(1,0))
        self.assertEqual(self.state()['ingestion_deadline_epoch'],deadline)
    def test_checkpoint_failure_after_possible_commit_never_reaches_post(self):
        def fail(j):
            if j.value['knowledge_registration'][FID].get('save_node_recovery'):
                j.persisted=copy.deepcopy(j.value);raise TimeoutError()
        self.job.journal.hook=fail
        with self.assertRaisesRegex(ValueError,'checkpoint_unconfirmed'):self.run_gate()
        self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_crash_after_reservation_never_posts_on_resume(self):
        def crash(j):
            if j.value['knowledge_registration'][FID].get('save_node_recovery'):
                j.persisted=copy.deepcopy(j.value);raise Crash()
        self.job.journal.hook=crash
        with self.assertRaises(Crash):self.run_gate()
        self.restart()
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_crash_after_commit_reuses_original_branch(self):
        self.api.post_fault='crash_after_accept'
        with self.assertRaises(Crash):self.run_gate()
        self.restart();self.run_gate();self.assertEqual(len(self.api.posts),1)
    def test_prior_branch_blocks_new_mutation(self):
        self.api.prior=[self.api.branch]
        with self.assertRaisesRegex(ValueError,'prior_rerun_exists'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_invalid_plan_never_posts(self):
        for key,value in [('node_key','root.other'),('workflow_id','other'),('source_execution_id','other'),
                          ('validation',{'ok':False}),('available_modes',['continue_from_node_with_overrides']),
                          ('affected_downstream_nodes',[]),('candidates',[]),('rerun_contract_hash','wrong')]:
            with self.subTest(key=key):
                original=copy.deepcopy(self.api.plan);self.api.plan[key]=value
                with self.assertRaisesRegex(ValueError,'plan_not_safe'):self.run_gate()
                self.assertEqual(self.api.posts,[]);self.api.plan=original
    def test_unrecognized_error_or_changed_file_cannot_authorize_node_rerun(self):
        self.api.old['error']=SINK.replace('Internal Server Error','Forbidden')
        with self.assertRaisesRegex(ValueError,'requires_backend_repair'):self.run_gate()
        self.assertEqual(self.api.posts,[])
        self.api.old['error']=SINK;self.api.input['file_id']='wrong'
        with self.assertRaisesRegex(ValueError,'execution_identity_mismatch'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_bad_ack_is_blocked_and_never_resubmitted(self):
        self.api.bad_ack=True
        with self.assertRaisesRegex(ValueError,'rerun_identity_mismatch'):self.run_gate()
        self.api.hide_new=True;self.restart()
        with self.assertRaisesRegex(ValueError,'recovery_blocked'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
    def test_successful_branch_alone_never_replaces_source_gate(self):
        self.api.hide_new=True
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.state()['save_node_recovery']['rerun']['status'],'succeeded')
        self.assertFalse(self.state().get('succeeded',False));self.assertEqual(len(self.api.posts),1)
    def test_failed_branch_exhausts_one_attempt(self):
        self.api.hide_new=True;self.api.branch['status']='failed'
        with self.assertRaisesRegex(ValueError,'recovery_exhausted'):self.run_gate()
        self.restart()
        with self.assertRaisesRegex(ValueError,'recovery_blocked'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
    def test_unknown_submission_branch_identity_or_input_mismatch_is_blocked(self):
        self.api.post_fault='after_accept';self.api.hide_new=True
        self.job.state['knowledge_registration']={FID:dict(ingestion_deadline_epoch=1010)}
        kb.recover_lineage(self.job,FID,self.state())
        for key,value in [('source_execution_id','other'),('source_node_execution_id','other'),
                          ('mode','other'),('source_case_id','other'),('new_workflow_execution_id',OLD)]:
            with self.subTest(key=key):
                original=self.api.branch[key];self.api.branch[key]=value
                with self.assertRaisesRegex(ValueError,'rerun_identity_mismatch'):
                    recover_save_node(self.job,FID,self.state(),deadline=1010)
                self.api.branch[key]=original
        self.api.new_input['volume_id']=1
        with self.assertRaisesRegex(ValueError,'rerun_input_changed'):
            recover_save_node(self.job,FID,self.state(),deadline=1010)
        self.assertEqual(len(self.api.posts),1)
    def test_changed_batch_cannot_adopt_reservation(self):
        self.api.post_fault='crash_after_accept'
        with self.assertRaises(Crash):self.run_gate()
        self.api.hide_new=True;self.restart();self.job.state['prefix']='different-batch'
        with self.assertRaisesRegex(ValueError,'checkpoint_identity_mismatch'):self.run_gate()
        self.assertEqual(len(self.api.posts),1)
    def test_deadline_after_reservation_prevents_post(self):
        def expire(j):
            if j.value['knowledge_registration'][FID].get('save_node_recovery'):self.clock.advance(11)
        self.job.journal.hook=expire
        with self.assertRaisesRegex(ValueError,'ingestion_deadline'):self.run_gate()
        self.assertEqual(self.api.posts,[])
    def test_ambiguous_branch_after_unknown_post_stays_read_only(self):
        self.api.post_fault='after_accept';self.api.hide_new=True
        self.job.state['knowledge_registration']={FID:dict(ingestion_deadline_epoch=1010)}
        kb.recover_lineage(self.job,FID,self.state());self.api.prior=[dict(self.api.branch,rerun_id='another')]
        with self.assertRaisesRegex(ValueError,'rerun_ambiguous'):
            recover_save_node(self.job,FID,self.state(),deadline=1010)
        self.assertEqual(len(self.api.posts),1)


class DiagnosticFallbackTests(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI();self.job=Job(self.api);self.api.job=self.job
    def test_transient_file_facts_uses_all_small_pages_including_active_execution(self):
        original=self.api.request
        self.api.list_prefix=[dict(execution_id='unrelated-'+str(i),file_id='other') for i in range(10)]
        self.api.list_prefix.append(dict(self.api.original_list,execution_id='active',status='running'))
        def request(path,*args,**kwargs):
            if urlsplit(path).path.endswith('/file-executions'):raise TimeoutError()
            return original(path,*args,**kwargs)
        with patch.object(self.api,'request',side_effect=request),patch.object(kb,'emit'):
            facts=kb.execution_facts(self.job,FID)
        self.assertEqual([v['execution_id'] for v in facts],['active',OLD])
        self.assertEqual(self.api.posts,[])
    def test_nontransient_diagnostic_error_does_not_expand_recovery(self):
        with patch.object(self.api,'request',side_effect=ValueError('moi_http_403')):
            with self.assertRaisesRegex(ValueError,'moi_http_403'):kb.execution_facts(self.job,FID)
        self.assertEqual(self.api.posts,[])
    def test_partial_or_duplicate_pages_cannot_prove_absence(self):
        for data in [dict(executions=[],total=1),dict(executions=[self.api.original_list]*2,total=2)]:
            with self.subTest(data=data):
                def request(path,*args,**kwargs):
                    if path.split('?')[0].endswith('/file-executions'):raise TimeoutError()
                    return data
                with patch.object(self.api,'request',side_effect=request),patch.object(kb,'emit'):
                    with self.assertRaisesRegex(ValueError,'list_incomplete|list_changed'):
                        kb.execution_facts(self.job,FID)
                self.assertEqual(self.api.posts,[])


if __name__=='__main__':unittest.main()
