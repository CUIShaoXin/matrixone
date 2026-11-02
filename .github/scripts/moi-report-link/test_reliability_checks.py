import unittest
from unittest.mock import patch

import reliability_checks as checks
from cloud_preflight import Failure
from test_knowledge_recovery import Job,FakeAPI,FID,OLD


class ReliabilitySmokeTests(unittest.TestCase):
    def wrap(self,api,wrong_input=False,task_child=False,wrong_source=False):
        original=api.request
        def request(path,*args,**kwargs):
            if path.endswith('/executions/'+OLD):
                return dict(execution=dict(execution_id=OLD,workflow_id=checks.KB_WORKFLOW_ID,status='completed',execution_mode='task_by_version' if task_child else 'volume_trigger',input_payload=dict(file_id='wrong' if wrong_input else FID,volume_id=140002,source_type='other' if wrong_source else 'volume_trigger',workflow_app_id=checks.KB_WORKFLOW_ID)))
            return original(path,*args,**kwargs)
        return request
    def test_read_only_sample_stops_at_matching_success_without_scanning_old_history(self):
        api=FakeAPI();job=Job(api);api.job=job;api.original_list['status']='completed'
        api.list_prefix=[dict(execution_id='unrelated-'+str(i),file_id='other') for i in range(10)]
        original=self.wrap(api)
        def request(path,*args,**kwargs):
            if 'offset=20' in path:raise AssertionError('unnecessary history scan')
            value=original(path,*args,**kwargs)
            if 'executions?' in path:value['total']=2000
            return value
        # The second small page may be full in production; the matching row
        # must be returned before querying the next page or interpreting absence.
        with patch.object(api,'request',side_effect=request):
            self.assertEqual(checks.observed_file_execution(job,FID,None)['execution_id'],OLD)
        self.assertEqual(api.posts,[])
    def test_non_success_or_changed_identity_is_never_reported_as_verified(self):
        for field,value in [('status','failed'),('workflow_id','other'),('execution_mode','one_shot')]:
            with self.subTest(field=field):
                api=FakeAPI();job=Job(api);api.job=job
                api.original_list['status']='completed';api.original_list[field]=value
                with self.assertRaisesRegex(Failure,'not_successful'):
                    checks.observed_file_execution(job,FID,None)
                self.assertEqual(api.posts,[])
    def test_manual_delivery_without_dispatch_id_requires_actual_original_input(self):
        api=FakeAPI();job=Job(api);api.job=job
        api.original_list.update(status='completed',dispatch_job_id='')
        with patch.object(api,'request',side_effect=self.wrap(api)):
            self.assertEqual(checks.observed_file_execution(job,FID,None)['execution_id'],OLD)
        self.assertEqual(api.posts,[])
    def test_actual_wrong_file_input_blocks_even_with_success_summary(self):
        api=FakeAPI();job=Job(api);api.job=job;api.original_list['status']='completed'
        with patch.object(api,'request',side_effect=self.wrap(api,wrong_input=True)):
            with self.assertRaisesRegex(Failure,'not_successful'):
                checks.observed_file_execution(job,FID,None)
        self.assertEqual(api.posts,[])
    def test_completed_child_task_requires_original_volume_trigger_input(self):
        api=FakeAPI();job=Job(api);api.job=job
        api.original_list.update(status='completed',execution_mode='task_by_version',dispatch_job_id='')
        with patch.object(api,'request',side_effect=self.wrap(api,task_child=True)):
            self.assertEqual(checks.observed_file_execution(job,FID,None)['execution_id'],OLD)
        self.assertEqual(api.posts,[])
    def test_arbitrary_child_task_source_cannot_pass(self):
        api=FakeAPI();job=Job(api);api.job=job
        api.original_list.update(status='completed',execution_mode='task_by_version',dispatch_job_id='')
        with patch.object(api,'request',side_effect=self.wrap(api,task_child=True,wrong_source=True)):
            with self.assertRaisesRegex(Failure,'not_successful'):
                checks.observed_file_execution(job,FID,None)
        self.assertEqual(api.posts,[])


if __name__=='__main__':unittest.main()
