import copy
import hashlib
import unittest
import urllib.error
import uuid
from unittest.mock import patch

from cloud_daily import WORKSPACE
from kimi_recovery import run_review
from test_pipeline_recovery import Job, Model


class PendingAuditRecoveryTests(unittest.TestCase):
    def setup_pending(self, state='completed'):
        api=Model([])
        job=Job(api)
        digest=hashlib.sha256(b'source').hexdigest()
        contract=hashlib.sha256(b'prompt').hexdigest()
        rid=str(uuid.uuid5(uuid.NAMESPACE_URL,job.state['prefix']+'/repo_audit/'+digest+'/'+contract+'/0'))
        suffix=hashlib.sha256((WORKSPACE+'\x00'+rid).encode()).hexdigest()[:48]
        saved=dict(context_sha256=digest,contract_sha256=contract,started_epoch=100,status='planned',
                   attempts=[dict(number=1,request_id=rid,status='planned',started_epoch=101)])
        job.state['model_tasks']={'repo_audit':saved}
        task=dict(id='art-'+suffix,status={'state':state},metadata={'manifestId':'arm-'+suffix})
        api.replies=[task]
        return api,job,saved,task

    def run_audit(self,job):
        with patch('kimi_recovery.time.time',return_value=10000):
            return run_review(job,'repo','audit','source','prompt',lambda t:t['id'],
                              poll_seconds=0,recover_pending_submission=True)

    def test_completed_original_task_is_read_after_deadline_without_new_inference(self):
        api,job,saved,task=self.setup_pending()
        self.assertEqual(self.run_audit(job),task['id'])
        self.assertEqual([r[0] for r in api.requests],['tasks/get'])
        self.assertEqual(api.requests[0][1],{'id':task['id']})
        self.assertEqual(saved['started_epoch'],100)
        self.assertEqual(len(saved['attempts']),1)
        self.assertTrue(saved['attempts'][0]['output_revalidated_without_inference'])
        self.assertTrue(saved['attempts'][0]['task_identity_recovered_read_only'])

    def test_still_working_original_task_does_not_refresh_budget_or_send(self):
        api,job,saved,_=self.setup_pending('working')
        with self.assertRaisesRegex(ValueError,'deadline_exceeded'):self.run_audit(job)
        self.assertEqual([r[0] for r in api.requests],['tasks/get'])
        self.assertEqual(saved['started_epoch'],100)
        self.assertNotIn('recovery_started_epoch',saved)

    def test_unconfirmed_read_never_becomes_permission_to_resubmit(self):
        for fault in (TimeoutError(),urllib.error.HTTPError('https://unused',404,'not found',{},None)):
            with self.subTest(fault=type(fault).__name__):
                api,job,saved,_=self.setup_pending()
                api.replies=[fault]
                with self.assertRaisesRegex(ValueError,'read_unconfirmed'):self.run_audit(job)
                self.assertEqual([r[0] for r in api.requests],['tasks/get'])
                self.assertNotIn('task_id',saved['attempts'][0])

    def test_task_and_manifest_identities_must_both_match_original_key(self):
        for field in ('id','manifestId'):
            with self.subTest(field=field):
                api,job,saved,task=self.setup_pending()
                if field=='id':task['id']='another-task'
                else:task['metadata']['manifestId']='another-manifest'
                api.replies=[task]
                with self.assertRaisesRegex(ValueError,'task_identity_mismatch'):self.run_audit(job)
                self.assertNotIn('task_id',saved['attempts'][0])
                self.assertEqual([r[0] for r in api.requests],['tasks/get'])

    def test_changed_request_key_is_rejected_before_any_task_read(self):
        api,job,saved,_=self.setup_pending()
        saved['attempts'][0]['request_id']=str(uuid.uuid4())
        with self.assertRaisesRegex(ValueError,'request_identity_mismatch'):self.run_audit(job)
        self.assertEqual(api.requests,[])

    def test_recovery_is_opt_in_and_does_not_change_source_review_contract(self):
        api,job,saved,_=self.setup_pending()
        before=copy.deepcopy(saved)
        with patch('kimi_recovery.time.time',return_value=10000):
            with self.assertRaisesRegex(ValueError,'deadline_exceeded'):
                run_review(job,'repo','audit','source','prompt',lambda t:t,poll_seconds=0)
        self.assertEqual(saved,before)
        self.assertEqual(api.requests,[])


if __name__=='__main__':unittest.main()
