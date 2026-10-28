"""Exercise status reconciliation through the CLI and durable adapter boundary."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from batch_context import BatchContext
from cloud_daily import json_bytes
import moi_actions
import orchestration_status
from resilient_storage import SignedObjects


class ConditionalObjects:
    def __init__(self):
        self.data = {}
        self.before_put = None

    def call(self, method, key, raw=None, headers=None, **kwargs):
        headers = headers or {}
        if method == 'GET':
            if key not in self.data: raise RuntimeError('minio_http_404')
            body = self.data[key]
            return 200, {'ETag': '"'+hashlib.sha256(body).hexdigest()+'"'}, body
        if method != 'PUT': raise AssertionError(method)
        if self.before_put:
            callback, self.before_put = self.before_put, None
            callback()
        if headers.get('if-none-match') == '*' and key in self.data:
            raise RuntimeError('minio_http_412')
        if 'if-match' in headers and headers['if-match'] != self.call('GET', key)[1]['ETag']:
            raise RuntimeError('minio_http_412')
        self.data[key] = raw
        return 200, {}, b''

    def publish(self, key, raw, kind):
        self.call('PUT', key, raw)


class ActionsReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        previous = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, previous)
        self.env = dict(MATRIX_PIPELINE_RUN_ID='terminal-batch', MATRIX_BUSINESS_DATE='2026-10-27',
                        MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_EXECUTION_MODE='production',
                        MOI_API_KEY='test', GITHUB_ACTIONS_TOKEN='test')
        self.ctx = BatchContext.from_env(self.env)
        self.store = ConditionalObjects()
        self.key = self.ctx.prefix+'/orchestration/status.json'
        self.saved = dict(self.ctx.record(), github=dict(run_id='123', attempt=1), status='running', sent=False,
            repositories=dict(matrixone=dict(commit='a'*40, stages=dict(component_scan='succeeded')),
                              taas=dict(commit='b'*40, stages=dict(component_scan='running'))),
            stages=dict(overall=dict(status='running'), report=dict(status='succeeded')),
            publication_file_id='report-file', report_url='https://reports.example.test/report', failures=[])
        self.save(self.saved)
        self.run = dict(id=123, run_attempt=1, status='completed', conclusion='cancelled',
            display_title='MOI security managed - terminal-batch', event='workflow_dispatch',
            path='.github/workflows/moi-managed-security.yml', repository=dict(full_name=moi_actions.REPOSITORY),
            html_url='https://github.com/CUIShaoXin/matrixone/actions/runs/123',
            updated_at='2026-10-27T13:10:00Z')
        self.actions = Mock()
        self.actions.request.side_effect = self.request
        self.api = Mock()
        self.files = {}
        def upload(name, raw):
            fid = 'status-'+hashlib.sha256(raw).hexdigest()
            self.files[fid] = raw
            return dict(file_id=fid)
        self.api.upload.side_effect = upload
        self.api.file.side_effect = self.files.__getitem__
        self.addCleanup(patch.stopall)
        patch.object(SignedObjects, 'call', autospec=True,
                     side_effect=lambda obj, *args, **kw: obj.call(*args, **kw)).start()
        self.scan = patch('managed_entry.scan').start()
        self.send = patch('daily_delivery.deliver').start()

    def save(self, value):
        self.store.publish(self.key, json_bytes(value), 'application/json')

    def request(self, path, payload=None):
        self.assertIsNone(payload, 'Reconciliation must only read GitHub.')
        self.assertEqual(path, '/actions/runs/123/attempts/1')
        return copy.deepcopy(self.run)

    def current(self):
        return json.loads(self.store.data[self.key])

    def reconcile(self):
        result = moi_actions.reconcile(self.actions, self.api, self.store, self.ctx)
        self.scan.assert_not_called()
        self.send.assert_not_called()
        self.api.rpc.assert_not_called()
        return result

    def test_cli_converges_cancelled_runner_and_preserves_accepted_evidence(self):
        with patch.dict(os.environ, self.env, clear=True), \
             patch('sys.argv', ['orchestration_status.py', '--reconcile-actions']), \
             patch('cloud_daily.DailyAPI', return_value=self.api), \
             patch('resilient_storage.Objects.from_workspace', return_value=self.store), \
             patch.object(moi_actions, 'GitHubActions', return_value=self.actions), \
             contextlib.redirect_stdout(io.StringIO()):
            orchestration_status.main()
        value = self.current()
        self.assertEqual(value['status'], 'cancelled')
        self.assertEqual(value['github'], dict(run_id='123', attempt=1))
        self.assertIsNone(value['sent'])
        self.assertEqual(value['repositories']['matrixone']['stages']['component_scan'], 'succeeded')
        self.assertEqual(value['repositories']['taas']['stages']['component_scan'], 'unknown')
        self.assertEqual(value['report_url'], self.saved['report_url'])
        self.assertEqual(value['stages']['github_actions']['conclusion'], 'cancelled')
        self.assertEqual(value['failure_stage'], 'github_actions')
        self.scan.assert_not_called()
        self.send.assert_not_called()
        self.api.rpc.assert_not_called()
        self.assertIn(self.store.data[self.key], self.files.values())

    def test_github_success_does_not_manufacture_business_success(self):
        self.run['conclusion'] = 'success'
        self.reconcile()
        value = self.current()
        self.assertEqual(value['status'], 'incomplete')
        self.assertEqual(value['failures'][-1]['code'], 'github_success_without_business_completion')
        self.assertEqual(value['business_status'], 'running')

    def test_timeout_preserves_receipt_and_original_business_failure(self):
        self.run['conclusion'] = 'timed_out'
        self.saved.update(status='failed', sent=True, delivery_receipt_file_id='verified-receipt',
                          failures=[dict(stage='report', code='report_readback_failed')])
        self.save(self.saved)
        self.reconcile()
        value = self.current()
        self.assertEqual(value['status'], 'timed_out')
        self.assertTrue(value['sent'])
        self.assertEqual(value['delivery_receipt_file_id'], 'verified-receipt')
        self.assertIn(dict(stage='report', code='report_readback_failed'), value['failures'])

    def test_completed_business_no_send_remains_successful(self):
        self.env['MATRIX_EXECUTION_MODE'] = 'no_send'
        self.ctx = BatchContext.from_env(self.env)
        self.saved.update(execution_mode='no_send', status='succeeded', sent=False)
        self.save(self.saved)
        self.run['conclusion'] = 'success'
        self.reconcile()
        self.assertEqual(self.current()['status'], 'succeeded')
        self.assertFalse(self.current()['sent'])

    def test_older_attempt_cannot_overwrite_new_snapshot(self):
        newer = copy.deepcopy(self.saved)
        newer.update(github=dict(run_id='123', attempt=2), status='running', sent=None)
        def request(path, payload=None):
            observed = self.request(path, payload)
            self.save(newer)
            return observed
        self.actions.request.side_effect = request
        result = self.reconcile()
        self.assertFalse(result['terminal_applied'])
        self.assertEqual(self.current(), newer)

    def test_conditional_write_preserves_attempt_that_starts_after_read(self):
        newer = copy.deepcopy(self.saved)
        newer.update(github=dict(run_id='456', attempt=1), status='running', sent=None)
        def request(path, payload=None):
            observed = self.request(path, payload)
            def before_put():
                # The first PUT saves terminal evidence. Race only the status PUT.
                self.store.before_put = lambda: self.save(newer)
            self.store.before_put = before_put
            return observed
        self.actions.request.side_effect = request
        result = self.reconcile()
        self.assertFalse(result['terminal_applied'])
        self.assertEqual(self.current(), newer)

    def test_identity_mismatch_and_github_outage_leave_status_intact(self):
        original = self.store.data[self.key]
        for field, value in (('run_attempt', 2), ('display_title', 'another batch'),
                             ('event', 'push'), ('path', '.github/workflows/other.yml')):
            with self.subTest(field=field):
                run = dict(self.run, **{field:value})
                self.actions.request.side_effect = lambda *a, **kw: run
                with self.assertRaisesRegex(ValueError, 'github_run_identity_mismatch'):
                    self.reconcile()
                self.assertEqual(self.store.data[self.key], original)
        self.actions.request.side_effect = TimeoutError('private provider URL')
        with self.assertRaises(TimeoutError): self.reconcile()
        self.assertEqual(self.store.data[self.key], original)

    def test_nonterminal_run_keeps_running_and_does_not_upload_terminal(self):
        self.run.update(status='in_progress', conclusion=None)
        result = self.reconcile()
        self.assertFalse(result['terminal_applied'])
        self.assertEqual(self.current(), self.saved)
        self.api.upload.assert_not_called()

    def test_terminal_evidence_survives_moi_outage_and_replay_is_idempotent(self):
        self.api.upload.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): self.reconcile()
        self.assertEqual(self.current()['status'], 'cancelled')
        self.api.upload.side_effect = lambda name, raw: (self.files.update(recovered=raw) or dict(file_id='recovered'))
        first = orchestration_status.upload_saved(self.api, self.store, self.ctx)
        raw = self.store.data[self.key]
        second = orchestration_status.upload_saved(self.api, self.store, self.ctx)
        self.assertTrue(first['synced'] and second['synced'])
        self.assertEqual(first['file_id'], second['file_id'])
        self.assertEqual(self.store.data[self.key], raw)
        self.assertEqual(self.current()['failures'], [dict(stage='github_actions', code='github_actions_cancelled')])
        self.api.rpc.assert_not_called()

    def test_report_read_outage_cannot_block_durable_terminal_status(self):
        self.saved['report_details'] = dict(status='pending', error_type='TimeoutError')
        self.save(self.saved)
        self.api.file.side_effect = TimeoutError('private report URL')
        with self.assertRaises(TimeoutError): self.reconcile()
        value = self.current()
        self.assertEqual(value['status'], 'cancelled')
        self.assertEqual(value['report_details']['status'], 'pending')
        self.assertNotIn('private report URL', json.dumps(value))

    def test_missing_etag_refuses_to_overwrite_shared_snapshot(self):
        original_call = self.store.call
        def without_etag(method, key, *args, **kwargs):
            status, headers, raw = original_call(method, key, *args, **kwargs)
            return status, {} if key == self.key else headers, raw
        self.store.call = without_etag
        with self.assertRaisesRegex(ValueError, 'status_etag_required'): self.reconcile()
        self.assertEqual(self.current(), self.saved)

    def test_no_send_mode_conflict_is_rejected_before_reading_github(self):
        self.saved['execution_mode'] = 'no_send'
        self.save(self.saved)
        with self.assertRaisesRegex(ValueError, 'batch_execution_mode_conflict'): self.reconcile()
        self.actions.request.assert_not_called()

    def test_precheckout_cancellation_uses_dispatch_binding_without_manual_github_identity(self):
        del self.store.data[self.key]
        saved = dict(run_id=self.ctx.run_id, business_date=self.ctx.business_date,
            request=dict(inputs=dict(trigger_source='moi_api', execution_mode='production')),
            github_run_id=123, github_attempt=1)
        self.store.publish(self.ctx.prefix+'/orchestration/dispatch.json', json_bytes(saved), 'application/json')
        self.reconcile()
        value = self.current()
        self.assertEqual(value['status'], 'cancelled')
        self.assertEqual(value['github'], dict(run_id='123', attempt=1))
        self.assertEqual(value['repositories']['matrixone']['status'], 'waiting')
        self.assertIsNone(value['sent'])

    def test_registered_retry_before_first_heartbeat_supersedes_older_snapshot(self):
        old_execution = dict(self.ctx.record(), github=dict(run_id='123', attempt=1))
        retry = dict(self.ctx.record(), github=dict(run_id='456', attempt=1))
        self.store.publish(self.ctx.prefix+'/checkpoint.json', json_bytes(dict(
            executions=[old_execution, retry], published=True, publication_file_id='report-file')), 'application/json')
        self.store.publish(self.ctx.prefix+'/components/checkpoint.json', json_bytes(dict(
            repositories=dict(matrixone=dict(accepted=True), taas=dict(accepted=True), matrixflow=dict(accepted=True)))),
            'application/json')
        self.files['report-file'] = json_bytes(dict(url=self.saved['report_url'], expires_at_utc='2026-11-03T00:00:00Z'))
        def request(path, payload=None):
            self.assertEqual(path, '/actions/runs/456/attempts/1')
            self.assertIsNone(payload)
            return dict(self.run, id=456, html_url='https://github.com/CUIShaoXin/matrixone/actions/runs/456')
        self.actions.request.side_effect = request
        self.reconcile()
        value = self.current()
        self.assertEqual(value['github'], retry['github'])
        self.assertEqual(value['status'], 'cancelled')
        self.assertEqual(value['repositories']['taas']['stages']['component_scan'], 'succeeded')
        self.assertEqual(value['report_url'], self.saved['report_url'])
        self.assertEqual(value['executions'], [old_execution, retry])
        self.assertEqual(value['previous_execution']['github'], old_execution['github'])

    def test_new_snapshot_absent_from_older_journal_is_never_downgraded(self):
        old = dict(self.ctx.record(), github=dict(run_id='99', attempt=1))
        self.store.publish(self.ctx.prefix+'/checkpoint.json', json_bytes(dict(executions=[old])), 'application/json')
        self.reconcile()
        self.assertEqual(self.current()['github'], self.saved['github'])
        self.assertEqual(self.current()['status'], 'cancelled')

    def test_linked_dispatch_reads_exact_run_instead_of_recent_run_list(self):
        request = dict(ref='main', inputs=dict(mode='managed', runtime_ref='a'*40,
            run_id=self.ctx.run_id, business_date=self.ctx.business_date,
            trigger_source=self.ctx.trigger_source, execution_mode=self.ctx.execution_mode))
        saved = dict(schema='matrix_moi_dispatch_v1', request=request,
            request_sha256=hashlib.sha256(json_bytes(request)).hexdigest(),
            run_id=self.ctx.run_id, business_date=self.ctx.business_date, state='in_progress',
            created_at='2026-10-27T00:00:00Z', github_run_id=123, github_attempt=1)
        self.store.publish(self.ctx.prefix+'/orchestration/dispatch.json', json_bytes(saved), 'application/json')
        def request_run(path, payload=None):
            self.assertEqual(path, '/actions/runs/123')
            self.assertIsNone(payload)
            return dict(self.run, run_attempt=2)
        self.actions.request.side_effect = request_run
        result = moi_actions.dispatch(self.actions, self.store, self.ctx, 'a'*40, workflow_ref='main')
        self.assertEqual((result['github_run_id'], result['github_attempt'], result['conclusion']), (123, 2, 'cancelled'))


if __name__ == '__main__': unittest.main()
