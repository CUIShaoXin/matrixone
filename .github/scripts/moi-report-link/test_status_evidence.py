"""The retained artifact must expose stage facts even when MOI is unavailable."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import orchestration_status
from test_orchestration_recovery import MemoryObjects, context


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ctx = context()
        self.objects = MemoryObjects()
        self.api = Mock()
        self.directory = tempfile.TemporaryDirectory()
        self.previous = os.getcwd()
        os.chdir(self.directory.name)
        self.addCleanup(self.restore_directory)

    def restore_directory(self):
        os.chdir(self.previous)
        self.directory.cleanup()

    def original_status(self, *, sent=None):
        return dict(self.ctx.record(), schema='matrix_orchestration_status_v1',
            status='failed', sent=sent, failure_stage='scan',
            repositories={'taas': dict(branch='main', commit='a'*40,
                zip_bytes=123456, zip_sha256='b'*64,
                minio_key='snapshots/20261027/taas/taas-'+('a'*40)+'-gha-moi-recovery.zip',
                stages=dict(download='succeeded', validation='succeeded', storage='succeeded',
                            component_scan='failed', code_review='succeeded', api_port_review='succeeded'),
                component_failure=dict(code='component_scan_incomplete', error_type='ValueError',
                    workflow=dict(workflow_id='original-workflow', execution_id='original-execution',
                                     error_message='PRIVATE_EXCEPTION_BODY')))},
            stages=dict(report=dict(status='waiting'), delivery=dict(status='unknown', sent=sent)),
            failures=[dict(stage='components', repository='taas', code='component_scan_incomplete',
                           error_message='PRIVATE_EXCEPTION_BODY')],
            report_url='https://example.test/report?signature=PRIVATE_SIGNATURE',
            delivery_receipt_file_id='original-receipt' if sent else None,
            credential='PRIVATE_CREDENTIAL')

    def read_evidence(self):
        return json.loads(Path('out/orchestration/evidence.json').read_bytes())

    def test_moi_outage_retains_stage_facts_without_private_urls_or_error_bodies(self):
        original = self.original_status()
        self.api.upload.side_effect = TimeoutError('PRIVATE_EXCEPTION_BODY')
        with patch.object(orchestration_status, 'snapshot', return_value=original):
            with self.assertRaises(TimeoutError):
                orchestration_status.sync(self.api, self.objects, self.ctx)
        retained = self.read_evidence()
        source = self.objects.data[self.ctx.prefix+'/orchestration/status.json']
        self.assertEqual(retained['source_snapshot_sha256'], hashlib.sha256(source).hexdigest())
        self.assertEqual(retained['run_id'], self.ctx.run_id)
        self.assertEqual(retained['repositories']['taas']['commit'], 'a'*40)
        self.assertEqual(retained['repositories']['taas']['zip_sha256'], 'b'*64)
        self.assertEqual(retained['repositories']['taas']['minio_key'],
                         original['repositories']['taas']['minio_key'])
        self.assertEqual(retained['repositories']['taas']['stages']['storage'], 'succeeded')
        self.assertEqual(retained['repositories']['taas']['stages']['component_scan'], 'failed')
        self.assertEqual(retained['failures'][0]['code'], 'component_scan_incomplete')
        self.assertEqual(retained['repositories']['taas']['component_failure']['workflow']['execution_id'],
                         'original-execution')
        self.assertIsNone(retained['sent'])
        self.assertNotIn('PRIVATE_', json.dumps(retained))
        self.assertNotIn('report_url', retained)

    def test_status_only_replay_retains_original_receipt_and_never_executes_business(self):
        import managed_entry
        original = self.original_status(sent=True)
        raw = json.dumps(original).encode()
        self.objects.publish(self.ctx.prefix+'/orchestration/status.json', raw, 'application/json')
        self.api.upload.return_value = dict(file_id='status-file')
        self.api.file.return_value = raw
        with patch.object(managed_entry, 'scan') as scanner, patch.object(managed_entry, 'delivery') as sender:
            receipt = orchestration_status.upload_saved(self.api, self.objects, self.ctx)
        retained = self.read_evidence()
        self.assertTrue(receipt['synced'])
        self.assertTrue(retained['sent'])
        self.assertEqual(retained['delivery_receipt_file_id'], 'original-receipt')
        scanner.assert_not_called()
        sender.assert_not_called()

    def test_storage_outage_still_retains_the_observed_snapshot(self):
        original = self.original_status()
        self.objects.publish = Mock(side_effect=TimeoutError('PRIVATE_STORAGE_ERROR'))
        with patch.object(orchestration_status, 'snapshot', return_value=original):
            with self.assertRaises(TimeoutError):
                orchestration_status.sync(self.api, self.objects, self.ctx)
        retained = self.read_evidence()
        self.assertEqual(retained['run_id'], self.ctx.run_id)
        self.assertEqual(retained['repositories']['taas']['stages']['component_scan'], 'failed')
        self.api.upload.assert_not_called()

    def test_status_replay_preserves_actual_github_conclusion_and_original_retry(self):
        original = self.original_status()
        original['stages']['github_actions'] = dict(status='completed', conclusion='failure',
            url='https://example.test/run?PRIVATE_SIGNATURE')
        original['repositories']['taas']['component_attempts'] = [dict(number=1,
            label='taas_finalize', validation='rejected', workflow_status='completed',
            workflow_id='original-workflow', execution_id='original-execution',
            failure=dict(code='employee_marker_missing', error_message='PRIVATE_EXCEPTION_BODY'))]
        raw = json.dumps(original).encode()
        self.objects.publish(self.ctx.prefix+'/orchestration/status.json', raw, 'application/json')
        self.api.upload.return_value = dict(file_id='status-file')
        self.api.file.return_value = raw
        orchestration_status.upload_saved(self.api, self.objects, self.ctx)
        retained = self.read_evidence()
        self.assertEqual(retained['stages']['github_actions']['conclusion'], 'failure')
        attempt = retained['repositories']['taas']['component_attempts'][0]
        self.assertEqual(attempt['execution_id'], 'original-execution')
        self.assertEqual(attempt['validation'], 'rejected')
        self.assertEqual(attempt['failure']['code'], 'employee_marker_missing')
        self.assertNotIn('PRIVATE_', json.dumps(retained))

    def test_report_enrichment_failure_retains_evidence_before_propagating(self):
        original = self.original_status()
        original.update(publication_file_id='original-report', report_details=dict(status='pending'))
        raw = json.dumps(original).encode()
        self.objects.publish(self.ctx.prefix+'/orchestration/status.json', raw, 'application/json')
        self.api.file.side_effect = TimeoutError('PRIVATE_EXCEPTION_BODY')
        with self.assertRaises(TimeoutError):
            orchestration_status.upload_saved(self.api, self.objects, self.ctx)
        self.assertEqual(self.read_evidence()['publication_file_id'], 'original-report')
        self.api.upload.assert_not_called()

    def test_original_stage_reason_reaches_snapshot_and_artifact_during_moi_outage(self):
        from pipeline_telemetry import span
        with self.assertRaises(ValueError):
            with span('component_knowledge', repository='taas'):
                raise ValueError('model_phase_deadline_exceeded')
        self.api.upload.side_effect = TimeoutError('PRIVATE_EXCEPTION_BODY')
        with self.assertRaises(TimeoutError):
            orchestration_status.sync(self.api, self.objects, self.ctx)
        source = json.loads(self.objects.data[self.ctx.prefix+'/orchestration/status.json'])
        stage = source['stages']['component_knowledge:taas']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['safe_code'], 'model_phase_deadline_exceeded')
        retained = self.read_evidence()['stages']['component_knowledge:taas']
        self.assertEqual(retained['status'], 'failed')
        self.assertEqual(retained['safe_code'], 'model_phase_deadline_exceeded')

    def test_object_location_rejects_urls_and_traversal_without_losing_stage_state(self):
        for location in ('https://example.test/PRIVATE_TOKEN',
                         'snapshots/../PRIVATE_TOKEN',
                         'snapshots/20261027/taas.zip?signature=PRIVATE_TOKEN'):
            with self.subTest(location=location):
                original = self.original_status()
                original['repositories']['taas']['minio_key'] = location
                self.api.upload.side_effect = TimeoutError()
                with patch.object(orchestration_status, 'snapshot', return_value=original):
                    with self.assertRaises(TimeoutError):
                        orchestration_status.sync(self.api, self.objects, self.ctx)
                retained = self.read_evidence()
                self.assertNotIn('minio_key', retained['repositories']['taas'])
                self.assertEqual(retained['repositories']['taas']['stages']['storage'], 'succeeded')
                self.assertNotIn('PRIVATE_', json.dumps(retained))


if __name__ == '__main__':
    unittest.main()
