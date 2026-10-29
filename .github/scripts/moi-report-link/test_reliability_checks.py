import unittest
from unittest.mock import patch

import reliability_checks as checks
from cloud_preflight import Failure
from test_knowledge_recovery import Job,FakeAPI,FID,OLD


class ReliabilitySmokeTests(unittest.TestCase):
    def test_read_only_sample_stops_at_matching_success_without_scanning_old_history(self):
        api=FakeAPI();job=Job(api);api.job=job;api.original_list['status']='completed'
        api.list_prefix=[dict(execution_id='unrelated-'+str(i),file_id='other') for i in range(10)]
        original=api.request
        def request(path,*args,**kwargs):
            if 'offset=20' in path:raise AssertionError('unnecessary history scan')
            value=original(path,*args,**kwargs);value['total']=2000;return value
        # The second small page may be full in production; the matching row
        # must be returned before querying the next page or interpreting absence.
        with patch.object(api,'request',side_effect=request):
            self.assertEqual(checks.observed_file_execution(job,FID,None)['execution_id'],OLD)
        self.assertEqual(api.posts,[])
    def test_non_success_or_changed_identity_is_never_reported_as_verified(self):
        for field,value in [('status','failed'),('workflow_id','other'),('dispatch_job_id','')]:
            with self.subTest(field=field):
                api=FakeAPI();job=Job(api);api.job=job
                api.original_list['status']='completed';api.original_list[field]=value
                with self.assertRaisesRegex(Failure,'not_successful'):
                    checks.observed_file_execution(job,FID,None)
                self.assertEqual(api.posts,[])


if __name__=='__main__':unittest.main()
