"""MOI-owned batch requests through real dispatch HTTP and conditional storage."""
import datetime as dt
import contextlib
import io
import json
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

import moi_control
from cloud_daily import json_bytes
import test_dispatch_ownership as dispatch_fixture


class ControlBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dispatch_fixture.DispatchOwnershipTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store
        self.controller = moi_control.Controller(self.fixture.actions, Mock(), self.store)
        self.inputs = dict(owner_run_id='native-moidaily-run-1', business_date='2026-10-28',
            trigger_source='moi_manual', execution_mode='no_send', runtime_ref='a'*40,
            workflow_ref='moi-orchestration-18820')

    def bind_remote_run(self):
        fixture = self.fixture

        def accepted():
            request = fixture.requests[-1][2]
            run = dict(fixture.run, display_title='MOI security managed - '+request['inputs']['run_id'])
            fixture.run = run
            fixture.runs = [run]

        fixture.before_post_response = accepted

    def posts(self):
        return [item for item in self.fixture.requests if item[0] == 'POST']

    def test_start_persists_business_identity_and_owner_link_before_dispatch(self):
        self.bind_remote_run()
        original = self.fixture.before_post_response

        def accepted():
            batch = self.controller.lookup(self.inputs['owner_run_id'])
            self.assertEqual(batch['business_date'], '2026-10-28')
            self.assertEqual(batch['trigger_source'], 'moi_manual')
            self.assertEqual(batch['runtime_ref'], 'a'*40)
            self.assertEqual(batch['workflow_ref'], 'moi-orchestration-18820')
            self.assertEqual(batch['workspace_id'], moi_control.WORKSPACE)
            original()

        self.fixture.before_post_response = accepted
        result = self.controller.start(**self.inputs)
        self.assertEqual(result['dispatch']['state'], 'in_progress')
        self.assertEqual(result['dispatch']['github_run_id'], 123)
        self.assertEqual(self.posts()[0][2]['inputs']['run_id'], result['batch']['run_id'])
        self.assertNotEqual(result['batch']['run_id'], self.inputs['owner_run_id'])

    def test_restarted_controller_uses_the_original_batch_and_never_reposts(self):
        self.bind_remote_run()
        first = self.controller.start(**self.inputs)
        restarted = moi_control.Controller(self.fixture.actions, Mock(), self.store)
        second = restarted.start(**self.inputs)
        self.assertEqual(second['batch'], first['batch'])
        self.assertEqual(self.posts(), [('POST', self.posts()[0][1], self.posts()[0][2])])

    def test_production_sources_share_one_day_batch_and_keep_original_source(self):
        self.bind_remote_run()
        first = self.controller.start(**dict(self.inputs, execution_mode='production'))
        second = self.controller.start(**dict(self.inputs, execution_mode='production',
            owner_run_id='native-moidaily-run-2', trigger_source='moi_schedule'))
        self.assertEqual(first['batch'], second['batch'])
        self.assertEqual(second['batch']['run_id'], 'daily-20261028')
        self.assertEqual(second['batch']['trigger_source'], 'moi_manual')
        self.assertEqual(self.controller.lookup('native-moidaily-run-2'), first['batch'])
        self.assertEqual(self.posts(), [('POST', self.posts()[0][1], self.posts()[0][2])])

    def test_no_send_runs_are_independent_and_never_occupy_the_production_batch(self):
        first = self.controller.prepare(**self.inputs)
        second = self.controller.prepare(**dict(self.inputs, owner_run_id='native-moidaily-run-2'))
        production = self.controller.prepare(**dict(self.inputs, owner_run_id='native-moidaily-run-3',
            execution_mode='production'))
        self.assertNotEqual(first['run_id'], second['run_id'])
        self.assertNotIn('daily-20261028', (first['run_id'], second['run_id']))
        self.assertEqual(production['run_id'], 'daily-20261028')
        self.assertEqual(self.posts(), [])

    def test_changed_owner_request_is_rejected_without_another_post(self):
        self.controller.start(**self.inputs)
        original = self.posts()
        for change in (dict(runtime_ref='b'*40), dict(workflow_ref='main'),
                dict(business_date='2026-10-29'), dict(execution_mode='production')):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, 'moi_batch_request_conflict'):
                    self.controller.start(**dict(self.inputs, **change))
                self.assertEqual(self.posts(), original)

    def test_unknown_dispatch_is_only_observed_after_restart(self):
        self.fixture.post_status = 504
        first = self.controller.start(**self.inputs)
        self.assertEqual(first['dispatch']['state'], 'unknown')
        original = self.posts()
        again = self.controller.start(**self.inputs)
        self.assertEqual(again['dispatch']['state'], 'unknown')
        self.assertEqual(self.posts(), original)

    def test_query_missing_or_prepared_batch_never_creates_or_dispatches(self):
        with self.assertRaisesRegex(ValueError, 'moi_batch_not_found'):
            self.controller.status(self.inputs['owner_run_id'])
        self.assertEqual(self.store.data, {})
        batch = self.controller.prepare(**self.inputs)
        keys = set(self.store.data)
        result = self.controller.status(self.inputs['owner_run_id'])
        self.assertEqual(result['batch'], batch)
        self.assertEqual(result['dispatch']['state'], 'not_submitted')
        self.assertIsNone(result['snapshot'])
        self.assertEqual(set(self.store.data), keys)
        self.assertEqual(self.fixture.requests, [])

    def test_status_reads_the_bound_run_and_the_saved_stage_receipts(self):
        self.bind_remote_run()
        started = self.controller.start(**self.inputs)
        batch = started['batch']
        key = 'receipts/20261028/pipeline-'+batch['run_id']+'/orchestration/status.json'
        snapshot = dict(run_id=batch['run_id'], business_date=batch['business_date'],
            execution_mode='no_send', status='running', sent=False,
            repositories=dict(taas=dict(stages=dict(component_scan='running'))))
        self.store.publish(key, json_bytes(snapshot), 'application/json')
        original = self.posts()
        result = self.controller.status(self.inputs['owner_run_id'])
        self.assertEqual(result['snapshot'], snapshot)
        self.assertEqual(result['dispatch']['github_run_id'], 123)
        self.assertEqual(self.posts(), original)

    def test_default_date_is_shanghai_today_and_resume_preserves_the_original_date(self):
        inputs = dict(self.inputs)
        inputs.pop('business_date')
        before_midnight_utc = dt.datetime(2026, 10, 27, 23, 30, tzinfo=dt.timezone.utc)
        first = self.controller.prepare(**inputs, now=before_midnight_utc)
        self.assertEqual(first['business_date'], '2026-10-28')
        next_day = before_midnight_utc+dt.timedelta(days=1)
        self.assertEqual(self.controller.prepare(**inputs, now=next_day), first)

    def test_lost_batch_write_ack_recovers_the_same_identity_without_dispatch(self):
        original = self.store.call

        def lost_ack(method, key, *args, **kwargs):
            result = original(method, key, *args, **kwargs)
            if method == 'PUT' and '/moi-batches/' in key:
                self.store.call = original
                raise TimeoutError()
            return result

        self.store.call = lost_ack
        with self.assertRaises(TimeoutError):
            self.controller.prepare(**self.inputs)
        saved = next(json.loads(raw) for key, raw in self.store.data.items() if '/moi-batches/' in key)
        recovered = self.controller.prepare(**self.inputs)
        self.assertEqual(recovered, saved)
        self.assertEqual(self.posts(), [])

    def test_invalid_configuration_is_rejected_before_storage_or_remote_calls(self):
        for change in (dict(owner_run_id=''), dict(trigger_source='github_manual'),
                dict(runtime_ref='main'), dict(business_date='2026-02-30'),
                dict(execution_mode='test_group'), dict(workflow_ref='')):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.controller.prepare(**dict(self.inputs, **change))
                self.assertEqual(self.store.data, {})
                self.assertEqual(self.fixture.requests, [])

    def test_lost_first_write_ack_across_midnight_keeps_the_reserved_business_date(self):
        inputs = dict(self.inputs)
        inputs.pop('business_date')
        before_midnight = dt.datetime(2026, 10, 28, 15, 59, tzinfo=dt.timezone.utc)
        original = self.store.call

        def lost_ack(method, key, *args, **kwargs):
            result = original(method, key, *args, **kwargs)
            if method == 'PUT':
                self.store.call = original
                raise TimeoutError()
            return result

        self.store.call = lost_ack
        with self.assertRaises(TimeoutError):
            self.controller.prepare(**inputs, now=before_midnight)
        recovered = self.controller.prepare(**inputs, now=before_midnight+dt.timedelta(minutes=2))
        self.assertEqual(recovered['business_date'], '2026-10-28')
        self.assertEqual(self.controller.lookup(inputs['owner_run_id']), recovered)
        self.assertEqual(self.posts(), [])

    def failed_run(self):
        self.bind_remote_run()
        result = self.controller.start(**self.inputs)
        self.fixture.run.update(status='completed', conclusion='failure')
        return result['batch']

    def test_resume_persists_one_rerun_and_observes_the_real_new_attempt(self):
        batch = self.failed_run()

        def restarted():
            self.fixture.run.update(status='in_progress', conclusion=None, run_attempt=2)

        self.fixture.before_post_response = restarted
        result = self.controller.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(result['batch'], batch)
        self.assertEqual(result['dispatch']['github_attempt'], 2)
        self.assertEqual(result['retry']['state'], 'in_progress')
        original = self.posts()
        again = self.controller.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(again['dispatch']['github_attempt'], 2)
        self.assertEqual(self.posts(), original)
        self.assertEqual(original[-1], ('POST', '/repos/CUIShaoXin/matrixone/actions/runs/123/rerun', {}))

    def test_unknown_rerun_is_not_repeated_while_the_old_attempt_is_still_visible(self):
        self.failed_run()
        self.fixture.post_status = 504
        first = self.controller.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(first['retry']['state'], 'unknown')
        original = self.posts()
        restarted = moi_control.Controller(self.fixture.actions, Mock(), self.store)
        again = restarted.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(again['retry']['state'], 'unknown')
        self.assertEqual(self.posts(), original)

    def test_confirmed_send_requires_state_sync_without_rerunning_business(self):
        self.inputs['execution_mode'] = 'production'
        batch = self.failed_run()
        ctx = self.controller.context(batch)
        self.store.publish(ctx.prefix+'/orchestration/status.json', json_bytes(dict(
            run_id=batch['run_id'], business_date=batch['business_date'], execution_mode='production',
            status='failed', sent=True, delivery_receipt_file_id='verified-receipt')), 'application/json')
        original = self.posts()
        result = self.controller.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(result['retry']['state'], 'status_sync_required')
        self.assertEqual(self.posts(), original)

    def test_retry_limit_and_existing_legacy_batch_never_start_another_execution(self):
        self.failed_run()
        self.fixture.run.update(run_attempt=2)
        original = self.posts()
        with self.assertRaisesRegex(ValueError, 'github_retry_limit_reached'):
            self.controller.resume(self.inputs['owner_run_id'], max_retries=1)
        self.assertEqual(self.posts(), original)
        legacy = self.controller.prepare(**dict(self.inputs, owner_run_id='legacy-owner', execution_mode='production'))
        ctx = self.controller.context(legacy)
        self.store.publish(ctx.prefix+'/checkpoint.json', json_bytes(dict(run_id=ctx.run_id, published=True)), 'application/json')
        with self.assertRaisesRegex(ValueError, 'existing_batch_requires_reconciliation'):
            self.controller.start(**dict(self.inputs, owner_run_id='legacy-owner', execution_mode='production'))
        self.assertEqual(self.posts(), original)


class ControlCLITests(unittest.TestCase):
    def test_missing_moi_connection_returns_an_explicit_blocker_without_dispatch(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output), \
                patch.object(moi_control.subprocess, 'run') as github:
            self.assertEqual(moi_control.main(['status', '--owner-run-id', 'native-run']), 1)
        self.assertEqual(json.loads(output.getvalue()), dict(operation='status', status='blocked',
            error_type='Failure', code='missing_moi_api_key'))
        github.assert_not_called()

    def test_managed_cli_uses_only_the_execution_repository_without_exporting_credentials(self):
        with patch.object(moi_control.subprocess, 'run', return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b'{"workflow_runs":[]}', stderr=b'')) as run:
            result = moi_control.GitHubCLI().request('/actions/workflows/moi-managed-security.yml/runs?per_page=100')
        self.assertEqual(result, dict(workflow_runs=[]))
        self.assertEqual(run.call_args.args[0], ['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
            '/repos/CUIShaoXin/matrixone/actions/workflows/moi-managed-security.yml/runs?per_page=100'])

    def test_cli_failure_exposes_only_the_http_code(self):
        private = b'HTTP 401: hidden-token-and-private-url'
        with patch.object(moi_control.subprocess, 'run', return_value=subprocess.CompletedProcess(
                args=[], returncode=1, stdout=b'', stderr=private)):
            with self.assertRaises(moi_control.urllib.error.HTTPError) as caught:
                moi_control.GitHubCLI().request('/actions/runs/123')
        self.assertEqual(caught.exception.code, 401)
        self.assertNotIn('hidden-token', str(caught.exception))

if __name__ == '__main__':
    unittest.main()
