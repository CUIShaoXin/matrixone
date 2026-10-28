"""Dispatch recovery at the real HTTP and conditional object-store boundaries."""
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch

from batch_context import BatchContext
from cloud_daily import json_bytes
import moi_actions
from resilient_storage import SignedObjects
from test_actions_reconciliation import ConditionalObjects


class DispatchOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.ctx = BatchContext.from_env(dict(MATRIX_PIPELINE_RUN_ID='dispatch-recovery',
            MATRIX_BUSINESS_DATE='2026-10-27', MATRIX_TRIGGER_SOURCE='moi_api',
            MATRIX_EXECUTION_MODE='no_send'))
        self.store = ConditionalObjects()
        self.key = self.ctx.prefix+'/orchestration/dispatch.json'
        self.requests = []
        self.before_post_response = None
        self.before_run_response = None
        self.post_status = 204
        self.runs = []
        self.run = dict(id=123, run_attempt=1, status='in_progress', conclusion=None,
            display_title='MOI security managed - '+self.ctx.run_id,
            event='workflow_dispatch', path='.github/workflows/'+moi_actions.WORKFLOW,
            repository=dict(full_name=moi_actions.REPOSITORY),
            html_url='https://github.com/'+moi_actions.REPOSITORY+'/actions/runs/123',
            created_at='2099-01-01T00:00:00Z')
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fixture.requests.append(('POST', self.path, payload))
                if fixture.before_post_response:
                    callback, fixture.before_post_response = fixture.before_post_response, None
                    callback()
                self.send_response(fixture.post_status)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_GET(self):
                fixture.requests.append(('GET', self.path, None))
                if '/actions/workflows/' in self.path:
                    result = dict(workflow_runs=copy.deepcopy(fixture.runs))
                else:
                    result = copy.deepcopy(fixture.run)
                    if fixture.before_run_response:
                        callback, fixture.before_run_response = fixture.before_run_response, None
                        callback()
                raw = json_bytes(result)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.addCleanup(patch.stopall)
        patch.object(moi_actions, 'BASE', 'http://127.0.0.1:'+str(self.server.server_port)
                     +'/repos/'+moi_actions.REPOSITORY).start()
        patch.object(SignedObjects, 'call', autospec=True,
                     side_effect=lambda obj, *args, **kwargs: obj.call(*args, **kwargs)).start()
        self.actions = moi_actions.GitHubActions('fixture-token')

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def dispatch(self):
        return moi_actions.dispatch(self.actions, self.store, self.ctx, 'a'*40,
                                    workflow_ref='moi-orchestration-18820')

    def current(self):
        return json.loads(self.store.data[self.key])

    def before_update(self, callback):
        original = self.store.call
        def intercept(method, key, raw=None, headers=None, **kwargs):
            if method == 'PUT' and key == self.key and not (headers or {}).get('if-none-match'):
                self.store.call = original
                callback()
            return original(method, key, raw, headers, **kwargs)
        self.store.call = intercept

    def test_late_dispatch_ack_preserves_run_linked_by_another_observer(self):
        def observe_while_post_is_pending():
            self.runs = [self.run]
            self.observer = self.dispatch()
            self.runs = []  # The run can leave the bounded recent list.
        self.before_post_response = observe_while_post_is_pending
        result = self.dispatch()
        self.assertEqual(self.observer['github_run_id'], 123)
        self.assertEqual(result['github_run_id'], 123)
        self.assertEqual(result['state'], 'in_progress')
        self.assertEqual(self.current()['github_run_id'], 123)
        self.assertEqual([item for item in self.requests if item[0] == 'POST'], [
            ('POST', '/repos/'+moi_actions.REPOSITORY+'/actions/workflows/'+moi_actions.WORKFLOW+'/dispatches',
             self.current()['request'])])

    def test_stale_poll_cannot_replace_a_newer_completed_attempt(self):
        self.runs = [self.run]
        self.dispatch()
        def finish_retry_before_old_response_returns():
            self.run.update(run_attempt=2, status='completed', conclusion='success')
            self.dispatch()
        self.before_run_response = finish_retry_before_old_response_returns
        result = self.dispatch()
        self.assertEqual((result['github_attempt'], result['state'], result['conclusion']),
                         (2, 'completed', 'success'))
        self.assertEqual(self.current(), result)

    def test_stale_poll_cannot_reopen_the_same_completed_attempt(self):
        self.runs = [self.run]
        self.dispatch()
        def finish_before_old_response_returns():
            self.run.update(status='completed', conclusion='failure')
            self.dispatch()
        self.before_run_response = finish_before_old_response_returns
        result = self.dispatch()
        self.assertEqual((result['github_attempt'], result['state'], result['conclusion']),
                         (1, 'completed', 'failure'))
        self.assertEqual(self.current(), result)

    def test_conditional_update_keeps_attempt_written_after_read(self):
        self.runs = [self.run]
        self.dispatch()
        def start_retry():
            saved = self.current()
            saved.update(github_attempt=2, state='in_progress', conclusion=None)
            self.store.data[self.key] = json_bytes(saved)
        self.run.update(status='completed', conclusion='cancelled')
        self.before_update(start_retry)
        result = self.dispatch()
        self.assertEqual((result['github_attempt'], result['state'], result['conclusion']),
                         (2, 'in_progress', None))
        self.assertEqual(self.current(), result)

    def test_a_second_github_run_cannot_replace_the_saved_binding(self):
        self.runs = [self.run]
        self.dispatch()
        def replace_after_read():
            saved = self.current()
            saved.update(github_run_id=456, github_attempt=1,
                         github_url='https://github.com/'+moi_actions.REPOSITORY+'/actions/runs/456')
            self.store.data[self.key] = json_bytes(saved)
        self.run.update(status='completed', conclusion='success')
        self.before_update(replace_after_read)
        with self.assertRaisesRegex(ValueError, 'github_run_correlation_conflict'):
            self.dispatch()
        self.assertEqual(self.current()['github_run_id'], 456)

    def test_contradictory_terminal_result_preserves_existing_evidence(self):
        self.run.update(status='completed', conclusion='success')
        self.runs = [self.run]
        self.dispatch()
        self.run.update(conclusion='failure')
        with self.assertRaisesRegex(ValueError, 'github_run_terminal_conflict'):
            self.dispatch()
        self.assertEqual(self.current()['conclusion'], 'success')

    def test_missing_etag_preserves_intent_and_retry_does_not_repost(self):
        original = self.store.call
        def without_etag(method, key, *args, **kwargs):
            status, headers, raw = original(method, key, *args, **kwargs)
            return status, {} if method == 'GET' else headers, raw
        self.store.call = without_etag
        with self.assertRaisesRegex(ValueError, 'dispatch_etag_required'):
            self.dispatch()
        self.runs = [self.run]
        with self.assertRaisesRegex(ValueError, 'dispatch_etag_required'):
            self.dispatch()
        self.assertEqual(self.current()['state'], 'submitting')
        posts = [item[2] for item in self.requests if item[0] == 'POST']
        self.assertEqual(posts, [self.current()['request']])

    def test_selected_workflow_ref_and_batch_are_sent_and_frozen_before_post(self):
        def inspect_intent():
            self.intent_at_post = self.current()
        self.before_post_response = inspect_intent
        result = self.dispatch()
        expected = dict(ref='moi-orchestration-18820', inputs=dict(mode='managed',
            runtime_ref='a'*40, run_id=self.ctx.run_id, business_date=self.ctx.business_date,
            trigger_source='moi_api', execution_mode='no_send'))
        self.assertEqual(self.intent_at_post['state'], 'submitting')
        self.assertEqual(self.intent_at_post['request'], expected)
        self.assertEqual(result['state'], 'submitted')
        self.assertNotIn('github_run_id', result)
        self.assertEqual([item[2] for item in self.requests if item[0] == 'POST'], [expected])
        before = copy.deepcopy(self.requests)
        for runtime, workflow_ref in [('a'*40, 'main'), ('b'*40, 'moi-orchestration-18820')]:
            with self.subTest(runtime=runtime, workflow_ref=workflow_ref):
                with self.assertRaisesRegex(ValueError, 'dispatch_batch_request_conflict'):
                    moi_actions.dispatch(self.actions, self.store, self.ctx, runtime, workflow_ref)
        self.assertEqual(self.requests, before, 'conflicting retries must never contact GitHub')
        self.assertEqual(self.current()['request'], expected)

    def test_missing_or_invalid_workflow_ref_is_rejected_before_io(self):
        for ref in [None, '', ' ', ' main', 'main\n', 'dev\nmain', 17]:
            with self.subTest(ref=ref):
                with self.assertRaisesRegex(ValueError, 'workflow_ref_required'):
                    moi_actions.dispatch(self.actions, self.store, self.ctx, 'a'*40, ref)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.store.data, {})

    def test_contended_update_returns_explicit_error_without_resubmitting(self):
        original = self.store.call
        def contended(method, key, raw=None, headers=None, **kwargs):
            if method == 'PUT' and (headers or {}).get('if-match'):
                raise RuntimeError('minio_http_412')
            return original(method, key, raw, headers, **kwargs)
        self.store.call = contended
        with self.assertRaisesRegex(ValueError, 'dispatch_update_contended'):
            self.dispatch()
        self.runs = [self.run]
        with self.assertRaisesRegex(ValueError, 'dispatch_update_contended'):
            self.dispatch()
        self.assertEqual(self.current()['state'], 'submitting')
        self.assertEqual([item[2] for item in self.requests if item[0] == 'POST'],
                         [self.current()['request']])

    def test_lost_storage_ack_recovers_without_another_dispatch(self):
        original = self.store.call
        def lose_ack(method, key, raw=None, headers=None, **kwargs):
            result = original(method, key, raw, headers, **kwargs)
            if method == 'PUT' and (headers or {}).get('if-match'):
                self.store.call = original
                raise TimeoutError('storage response lost after commit')
            return result
        self.store.call = lose_ack
        with self.assertRaises(TimeoutError):
            self.dispatch()
        self.assertEqual(self.current()['state'], 'submitted')
        self.run.update(status='completed', conclusion='success')
        self.runs = [self.run]
        result = self.dispatch()
        self.assertEqual((result['github_run_id'], result['state'], result['conclusion']),
                         (123, 'completed', 'success'))
        self.assertEqual([item[2] for item in self.requests if item[0] == 'POST'],
                         [self.current()['request']])

    def test_unknown_post_can_be_linked_later_without_resubmission(self):
        self.post_status = 504
        result = self.dispatch()
        self.assertEqual((result['state'], result['http_status']), ('unknown', 504))
        self.runs = [self.run]
        result = self.dispatch()
        self.assertEqual((result['github_run_id'], result['state']), (123, 'in_progress'))
        self.assertEqual([item[2] for item in self.requests if item[0] == 'POST'],
                         [self.current()['request']])

    def test_confirmed_rejection_is_retained_without_resubmission(self):
        self.post_status = 403
        result = self.dispatch()
        self.assertEqual((result['state'], result['http_status']), ('rejected', 403))
        self.assertEqual(self.dispatch(), result)
        self.assertEqual(self.requests, [
            ('POST', '/repos/'+moi_actions.REPOSITORY+'/actions/workflows/'+moi_actions.WORKFLOW+'/dispatches',
             result['request'])])


if __name__ == '__main__':
    unittest.main()
