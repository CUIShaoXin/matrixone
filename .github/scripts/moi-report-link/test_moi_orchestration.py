"""Entry-level orchestration regressions, without network or group sends."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class EntryRegressionTests(unittest.TestCase):
    def test_explicit_moi_batch_and_business_date_are_preserved(self):
        from batch_context import BatchContext
        env = dict(MATRIX_PIPELINE_RUN_ID='moi-batch', MATRIX_BUSINESS_DATE='2026-10-27',
                   MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_EXECUTION_MODE='no_send',
                   GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2')
        ctx = BatchContext.from_env(env, now=dt.datetime(2026, 10, 28, tzinfo=dt.timezone.utc))
        self.assertEqual((ctx.run_id, ctx.business_date, ctx.trigger_source),
                         ('moi-batch', '2026-10-27', 'moi_api'))
        self.assertEqual(ctx.github, dict(run_id='123', attempt=2))

    def test_conflicting_resume_identity_is_rejected(self):
        from batch_context import BatchContext
        with self.assertRaisesRegex(ValueError, 'batch_resume_identity_conflict'):
            BatchContext.from_env(dict(MATRIX_PIPELINE_RUN_ID='one', MATRIX_PIPELINE_RESUME_RUN_ID='two'))

    def test_invalid_business_date_or_source_is_rejected_before_io(self):
        from batch_context import BatchContext
        for values in (dict(MATRIX_BUSINESS_DATE='2026-02-30'), dict(MATRIX_TRIGGER_SOURCE='unknown')):
            with self.assertRaises(ValueError): BatchContext.from_env(values)

    def test_same_moi_batch_is_not_replaced_by_actions_attempt(self):
        from batch_context import BatchContext
        env = dict(MATRIX_PIPELINE_RUN_ID='stable', MATRIX_BUSINESS_DATE='2026-10-27',
                   MATRIX_TRIGGER_SOURCE='moi_manual', GITHUB_RUN_ID='456')
        first = BatchContext.from_env(dict(env, GITHUB_RUN_ATTEMPT='1'))
        retry = BatchContext.from_env(dict(env, GITHUB_RUN_ATTEMPT='2'))
        self.assertEqual(first.prefix, retry.prefix)
        self.assertNotEqual(first.github, retry.github)

    def test_scan_failure_prevents_delivery_and_returns_real_failure(self):
        import managed_entry
        with tempfile.TemporaryDirectory() as tmp, patch.object(managed_entry, 'scan', return_value=1), \
             patch.object(managed_entry, 'delivery') as send, patch.dict('os.environ', {'MATRIX_EXECUTION_MODE':'no_send'}), \
             patch.object(managed_entry, 'sync_status', return_value={'synced':True}):
            self.assertEqual(managed_entry.run(Path(tmp)), 1)
        send.assert_not_called()

    def test_no_send_reaches_preview_and_never_calls_production_sender(self):
        import managed_entry
        with tempfile.TemporaryDirectory() as tmp, patch.object(managed_entry, 'scan', return_value=0), \
             patch.object(managed_entry, 'delivery', return_value=0) as delivery, \
             patch.dict('os.environ', {'MATRIX_EXECUTION_MODE':'no_send'}), \
             patch.object(managed_entry, 'sync_status', return_value={'synced':True}):
            self.assertEqual(managed_entry.run(Path(tmp)), 0)
            self.assertEqual(delivery.call_args.kwargs, {'preview':True})



class PipelineEntryIntegrationTests(unittest.TestCase):
    def test_real_entry_collects_three_fixed_zip_objects_under_moi_identity(self):
        import contextlib
        import io
        import json
        import os
        import zipfile
        import daily_pipeline as pipeline
        from resilient_storage import sha256

        class MemoryObjects:
            def __init__(self): self.data = {}
            def call(self, method, key, **kwargs):
                if key not in self.data: raise RuntimeError('minio_http_404')
                return 200, {}, self.data[key]
            def publish(self, key, raw, kind): self.data[key] = raw
            def verify_object(self, key, size, digest):
                raw = self.data.get(key)
                return raw is not None and len(raw) == size and sha256(raw) == digest
            def put_verified(self, key, raw, digest, transfer, save):
                self.data[key] = raw
                if not self.verify_object(key, len(raw), digest): raise ValueError('readback_mismatch')
                save()

        class GitHub:
            token = 'test-in-memory'
            def __init__(self): self.requests = []
            def get(self, repo, path, binary=False):
                self.requests.append((repo, path))
                if path.startswith('/branches/'): return {'commit':{'sha':'a'*40}}
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, 'w') as archive:
                    archive.comment = b'a'*40
                    archive.writestr(repo.split('/')[-1]+'-root/go.mod', b'module test\ngo 1.24\n')
                return stream.getvalue()

        store, github = MemoryObjects(), GitHub()
        env = dict(MATRIX_PIPELINE_RUN_ID='moi-integration', MATRIX_BUSINESS_DATE='2026-10-26',
                   MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_PIPELINE_MODE='archives',
                   MATRIX_EXECUTION_MODE='no_send', GITHUB_RUN_ID='900', MOI_API_KEY='test')
        with tempfile.TemporaryDirectory() as tmp, patch.dict('os.environ', env, clear=True), \
             patch.object(pipeline, 'DailyAPI'), patch.object(pipeline.preflight.Objects, 'from_workspace', return_value=store), \
             patch.object(pipeline.preflight, 'GitHub', return_value=github), \
             patch('archive_transfer.tempfile.gettempdir', return_value=tmp):
            previous = os.getcwd()
            try:
                os.chdir(tmp)
                self.assertEqual(pipeline.main(), 0)
                status = json.loads(Path('out/pipeline/status.json').read_bytes())
            finally: os.chdir(previous)
        self.assertEqual((status['run_id'], status['date']), ('moi-integration', '2026-10-26'))
        root = json.loads(store.data['receipts/20261026/pipeline-moi-integration/checkpoint.json'])
        self.assertEqual(list(root['archives']), ['matrixone', 'taas', 'matrixflow'])
        for repo in ('matrixone', 'taas', 'matrixflow'):
            proof = root['archives'][repo]
            self.assertEqual(proof['commit'], 'a'*40)
            self.assertTrue(store.verify_object(proof['key'], proof['bytes'], proof['sha256']))

class StatusAndDispatchTests(unittest.TestCase):
    def context(self):
        from batch_context import BatchContext
        return BatchContext.from_env(dict(MATRIX_PIPELINE_RUN_ID='batch', MATRIX_BUSINESS_DATE='2026-10-27',
            MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_EXECUTION_MODE='no_send'))

    def test_status_replay_only_uploads_saved_bytes_and_verifies_moi_readback(self):
        import json
        import orchestration_status as status
        from unittest.mock import Mock
        raw = json.dumps(dict(run_id='batch', business_date='2026-10-27', status='succeeded')).encode()
        api, objects = Mock(), Mock()
        objects.call.return_value = (200, {}, raw)
        api.upload.return_value = dict(file_id='moi-file')
        api.file.return_value = raw
        with patch.object(status, 'read_json', return_value=None):
            result = status.upload_saved(api, objects, self.context())
        self.assertEqual(result['file_id'], 'moi-file')
        self.assertTrue(result['synced'])
        self.assertEqual(api.upload.call_args.args[1], raw)
        api.rpc.assert_not_called()

    def test_exact_completed_actions_run_is_correlated(self):
        import moi_actions as bridge
        from unittest.mock import Mock
        actions, objects = Mock(), Mock()
        actions.request.side_effect = [None, dict(workflow_runs=[dict(display_title='MOI security managed - batch',
            created_at='2099-01-01T00:00:00Z', id=123, run_attempt=2, status='completed', conclusion='failure',
            event='workflow_dispatch', path='.github/workflows/moi-managed-security.yml',
            repository=dict(full_name=bridge.REPOSITORY),
            html_url='https://github.com/CUIShaoXin/matrixone/actions/runs/123')])]
        with patch.object(bridge, 'create_once', side_effect=lambda o,k,v:(True,v)):
            result = bridge.dispatch(actions, objects, self.context(), 'a'*40)
        self.assertEqual((result['github_run_id'], result['github_attempt'], result['conclusion']), (123,2,'failure'))

    def test_moi_readback_corruption_is_not_reported_as_synced(self):
        import json
        import orchestration_status as status
        from unittest.mock import Mock
        raw = json.dumps(dict(run_id='batch', business_date='2026-10-27')).encode()
        api, objects = Mock(), Mock()
        objects.call.return_value = (200, {}, raw)
        api.upload.return_value = dict(file_id='moi-file')
        api.file.return_value = b'corrupt'
        with patch.object(status, 'read_json', return_value=None):
            with self.assertRaisesRegex(ValueError, 'readback_mismatch'):
                status.upload_saved(api, objects, self.context())

    def test_dispatch_acceptance_is_submitted_until_real_run_is_found(self):
        import moi_actions as bridge
        from unittest.mock import Mock
        actions, objects = Mock(), Mock()
        actions.request.side_effect = [None, dict(workflow_runs=[])]
        with patch.object(bridge, 'create_once', side_effect=lambda o,k,v:(True,v)):
            result = bridge.dispatch(actions, objects, self.context(), 'a'*40)
        self.assertEqual(result['state'], 'submitted')
        self.assertNotIn('conclusion', result)
        self.assertEqual(actions.request.call_args_list[0].args[1]['inputs']['run_id'], 'batch')

    def test_uncertain_dispatch_is_correlated_without_resubmitting(self):
        import moi_actions as bridge
        from unittest.mock import Mock
        actions, objects = Mock(), Mock()
        actions.request.side_effect = [TimeoutError(), dict(workflow_runs=[]), dict(workflow_runs=[])]
        persisted = {}
        def claim(o,k,value):
            if persisted: return False, persisted.copy()
            persisted.update(value)
            return True, persisted.copy()
        def save(k,raw,kind):
            import json
            persisted.update(json.loads(raw))
        objects.publish.side_effect = save
        with patch.object(bridge, 'create_once', side_effect=claim):
            self.assertEqual(bridge.dispatch(actions, objects, self.context(), 'a'*40)['state'], 'unknown')
            self.assertEqual(bridge.dispatch(actions, objects, self.context(), 'a'*40)['state'], 'unknown')
        self.assertEqual([call.args[0].endswith('/dispatches') for call in actions.request.call_args_list],
                         [True, False, False])


if __name__ == '__main__': unittest.main()
