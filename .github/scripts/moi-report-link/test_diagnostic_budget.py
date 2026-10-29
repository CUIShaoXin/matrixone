"""A bounded diagnostic must not multiply timeouts in the generic API layer."""
import unittest
from unittest.mock import patch
import cloud_daily as cloud
import knowledge_gate as kb
from test_knowledge_recovery import FakeAPI,Job,FID


class DiagnosticBudgetTests(unittest.TestCase):
    def test_read_once_has_no_hidden_retries_or_sleeps(self):
        api=cloud.DailyAPI('offline-test')
        with patch.object(cloud.publication.ReportAPI,'request',side_effect=TimeoutError()) as request,\
             patch.object(cloud.time,'sleep') as sleep,patch('pipeline_telemetry.emit'):
            with self.assertRaises(TimeoutError):api.request('/workflow/test',timeout=15,retry=False)
        self.assertEqual(request.call_count,1);sleep.assert_not_called()
    def test_default_read_recovery_is_retained_for_unmodified_callers(self):
        api=cloud.DailyAPI('offline-test')
        with patch.object(cloud.publication.ReportAPI,'request',side_effect=[TimeoutError(),{'ok':True}]) as request,\
             patch.object(cloud.time,'sleep'),patch('pipeline_telemetry.emit'):
            self.assertEqual(api.request('/workflow/test'),{'ok':True})
        self.assertEqual(request.call_count,2)
    def test_mutations_never_gain_automatic_retries(self):
        api=cloud.DailyAPI('offline-test')
        with patch.object(cloud.publication.ReportAPI,'request',side_effect=TimeoutError()) as request,\
             patch.object(cloud.time,'sleep') as sleep,patch('pipeline_telemetry.emit'):
            with self.assertRaises(TimeoutError):api.request('/workflow/test',{},method='POST')
        self.assertEqual(request.call_count,1);sleep.assert_not_called()
    def test_fact_read_uses_original_remaining_budget_and_no_nested_retry(self):
        api=FakeAPI();job=Job(api);api.job=job
        with patch.object(api,'request',wraps=api.request) as request,patch.object(kb.time,'time',return_value=100):
            kb.execution_facts(job,FID,deadline=104)
        self.assertEqual(request.call_args.kwargs,{'timeout':4,'retry':False})
    def test_multi_page_inventory_cannot_refresh_its_read_deadline(self):
        api=FakeAPI();job=Job(api);api.job=job;clock=[100]
        def request(path,*args,**kwargs):
            clock[0]+=4
            return dict(items=[{}]*100)
        with patch.object(api,'request',side_effect=request) as read,\
             patch.object(kb.time,'time',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(ValueError,'ingestion_deadline'):kb.rows(api,deadline=105)
        self.assertEqual(read.call_count,2)
        self.assertEqual([c.kwargs['timeout'] for c in read.call_args_list],[5,1])


if __name__=='__main__':unittest.main()
