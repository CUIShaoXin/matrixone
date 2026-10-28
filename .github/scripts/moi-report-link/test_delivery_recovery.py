"""Offline failure/restart drills. No real API, object store, send or wall sleep."""
import copy
import datetime as dt
import json
import unittest
from collections import defaultdict, deque
from unittest.mock import patch

import daily_delivery as d
import test_daily_delivery as old

DATE = '2026-10-28'
BASE = 'daily/20261028/'
CLAIM = BASE + 'delivery-claim.json'
COMPLETE = BASE + 'delivery-completed.json'
NATIVE = BASE + 'native-delivery-receipt.json'
UPLOAD_CLAIM = BASE + 'native-receipt-upload-claim.json'
REAL_DATETIME = dt.datetime


class Crash(BaseException):
    """Process death must bypass all normal recovery handlers."""


class Clock:
    def __init__(self, at='2026-10-28T10:00:00+08:00'):
        self.origin = REAL_DATETIME.fromisoformat(at)
        self.elapsed = 0.0
        self.sleeps = []

    def now(self, tz=None):
        at = self.origin + dt.timedelta(seconds=self.elapsed)
        return at.astimezone(tz) if tz is not None else at.replace(tzinfo=None)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.elapsed += max(seconds, .001)


class FakeObjects:
    def __init__(self, clock):
        self.clock, self.values = clock, {}
        self.calls, self.faults = [], defaultdict(deque)

    def inject(self, method, key, stage, action):
        self.faults[method, key, stage].append(action)

    def fault(self, method, key, stage):
        queue = self.faults[method, key, stage]
        if queue:
            action = queue.popleft()
            if callable(action):
                action(self)
            else:
                raise action

    def call(self, method, key, raw=None, headers=None, timeout=None):
        self.calls.append((method, key, raw, copy.deepcopy(headers), self.clock.elapsed, timeout))
        self.fault(method, key, 'before')
        if method == 'GET':
            if key not in self.values:
                raise RuntimeError('minio_http_404')
            result = self.values[key]
        elif method == 'PUT':
            if headers and headers.get('if-none-match') == '*' and key in self.values:
                raise RuntimeError('minio_http_412')
            self.values[key] = raw
            result = b''
        else:
            raise AssertionError('unexpected storage operation: ' + method)
        self.fault(method, key, 'after')
        return 200, {}, result

    def publish(self, key, raw, content_type):
        self.call('PUT', key, raw, {'content-type': content_type})
        if self.call('GET', key)[2] != raw:
            raise ValueError('fake_readback_mismatch')

    def put_json(self, key, value):
        self.values[key] = d.json_bytes(value)

    def get_json(self, key):
        return json.loads(self.values[key])


class FakeAPI:
    def __init__(self, objects, backend=None):
        self.objects, self.clock = objects, objects.clock
        self.backend = backend if backend is not None else dict(task=None, files={}, names={}, sends=0, uploads=0)
        self.calls, self.faults = [], defaultdict(deque)

    def fault(self, operation):
        if self.faults[operation]:
            action = self.faults[operation].popleft()
            if callable(action):
                action()
            else:
                raise action

    @staticmethod
    def data(result):
        return result

    def make_task(self, claim):
        cid = 'original-call'
        return dict(id=claim['task_id'], status=dict(state='completed'), events=[
            dict(type='moi.tool.call', toolId='moi_wecom_robot_message', callId=cid,
                 arguments=dict(channel_instance_id=d.CHANNEL, msg_type='markdown', content=claim['content'])),
            dict(type='moi.tool.result', toolId='moi_wecom_robot_message', callId=cid,
                 output=dict(call_id=cid, tool_id='moi_wecom_robot_message',
                             created_at=self.clock.now(dt.timezone.utc).isoformat(),
                             output=dict(ok=True, operation='group_robot_send', request_id=cid, workspace_id=d.WORKSPACE)))])

    def rpc(self, method, params, rid):
        self.calls.append((method, copy.deepcopy(params), self.clock.elapsed))
        if method == 'message/send':
            # This is an in-memory fake, never a send tool or a network mutation.
            self.backend['sends'] += 1
            self.backend['task'] = self.make_task(self.objects.get_json(CLAIM))
            self.fault('message/send')
            return copy.deepcopy(self.backend['task'])
        if method != 'tasks/get':
            raise AssertionError(method)
        self.fault('tasks/get')
        task = self.backend['task']
        if task is None:
            raise RuntimeError('minio_http_404')
        if params['id'] != self.objects.get_json(CLAIM)['task_id']:
            raise AssertionError('read a different task')
        return copy.deepcopy(task)

    def request(self, path, payload):
        self.calls.append((path, copy.deepcopy(payload), self.clock.elapsed))
        if path != '/catalog/file/list':
            raise AssertionError('unexpected catalog mutation')
        self.fault('list')
        return dict(list=[dict(file_id=fid, origin_file_name=name) for fid, name in self.backend['names'].items()])

    def file(self, fid):
        self.calls.append(('file', fid, self.clock.elapsed))
        self.fault('file')
        if fid not in self.backend['files']:
            raise AssertionError('unexpected large report download')
        return self.backend['files'][fid]

    def upload(self, name, raw):
        self.calls.append(('upload', name, self.clock.elapsed))
        self.backend['uploads'] += 1
        self.fault('upload-before')
        fid = 'native-' + str(self.backend['uploads'])
        self.backend['files'][fid] = raw
        self.backend['names'][fid] = name
        self.fault('upload-after')
        return dict(file_id=fid, bytes=len(raw), sha256=d.sha(raw), readback_verified=True)


class Output:
    def mkdir(self, **kwargs):
        pass

    def __truediv__(self, name):
        return self

    def write_bytes(self, raw):
        self.raw = raw


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fresh()
        owner = self
        class DateTime(REAL_DATETIME):
            @classmethod
            def now(cls, tz=None):
                return owner.clock.now(tz)
        self.enterContext(patch.object(d.dt, 'datetime', DateTime))
        self.enterContext(patch.object(d.time, 'monotonic', side_effect=lambda: self.clock.elapsed))
        self.enterContext(patch.object(d.time, 'sleep', side_effect=lambda s: self.clock.sleep(s)))
        self.enterContext(patch.object(d.SignedObjects, 'call', side_effect=lambda obj, *a, **kw: obj.call(*a, **kw)))
        self.enterContext(patch.dict(d.os.environ, {}, clear=True))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('network forbidden')))
        self.enterContext(patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')))

    # TestCase.enterContext was added in Python 3.11; runtime also supports 3.9.
    def enterContext(self, cm):
        result = cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        return result

    def fresh(self, at='2026-10-28T10:00:00+08:00'):
        self.clock = Clock(at)
        self.objects = FakeObjects(self.clock)
        self.api = FakeAPI(self.objects)
        self.bundle = old.DeliveryTests().bundle()
        self.pointer = dict(schema='matrix_daily_ready_v1', date=DATE, scope='three-repositories',
                            prefix='receipts/20261028/pipeline-original', run_id='original',
                            commits={r: r + '-commit' for r in d.REPOS},
                            publication_file_id='file', publication_sha256='hash')
        self.bundle['root'].update(run_id=self.pointer['run_id'], commits=self.pointer['commits'])
        self.objects.put_json(BASE + 'ready.json', self.pointer)

    def seed_claim(self, legacy=False):
        claim = dict(schema='matrix_daily_claim_v1', date=DATE, channel_instance_id=d.CHANNEL,
                     task_id='original-task', attempt_id='original-attempt', content=d.compose(self.bundle, DATE),
                     publication_file_id='file', prefix=self.pointer['prefix'])
        if not legacy:
            claim.update(content_sha256=d.sha(claim['content'].encode()), report_identity=d.report_identity(self.pointer))
        self.objects.put_json(CLAIM, claim)
        self.api.backend['task'] = self.api.make_task(claim)
        return claim

    def seed_complete(self, claim=None, native=True):
        claim = claim or self.seed_claim()
        final = d.verify_send(self.api.backend['task'], claim)
        self.objects.put_json(COMPLETE, final)
        if native:
            artifact = self.api.upload('matrix-security-delivery-20261028.json', d.json_bytes(final))
            self.objects.put_json(NATIVE, artifact)
        self.api.calls.clear()
        self.objects.calls.clear()
        return final

    def run_delivery(self, **kwargs):
        with patch.object(d, 'check_bundle', return_value=self.bundle):
            return d.deliver(self.api, self.objects, DATE, poll_seconds=1, deadline_seconds=12, **kwargs)

    def recover(self, **kwargs):
        with patch.object(d, 'check_bundle', side_effect=AssertionError('report must not be downloaded')):
            return d.recover_delivery(self.api, self.objects, DATE, poll_seconds=1, deadline_seconds=12, **kwargs)

    def run_main(self, env=None, check=None):
        output = Output()
        values = dict(MOI_API_KEY='fake', MATRIX_EXPECTED_REPORT_DATE=DATE)
        values.update(env or {})
        with patch.dict(d.os.environ, values, clear=True), patch.object(d, 'Path', return_value=output), \
                patch.object(d, 'DailyAPI', return_value=self.api), \
                patch.object(d.Objects, 'from_workspace', return_value=self.objects), \
                patch.object(d, 'check_bundle', side_effect=check or (lambda *a: self.bundle)), patch('builtins.print'):
            code = d.main()
        return code, json.loads(output.raw)

    def assert_no_resend(self):
        self.assertEqual(self.api.backend['sends'], 0)
        self.assertNotIn('message/send', [c[0] for c in self.api.calls])

    def test_uncertain_submission_and_diagnostic_timeout_still_reads_original_task(self):
        self.api.faults['message/send'].append(TimeoutError())
        self.objects.inject('PUT', BASE + 'submission-uncertain.json', 'before', TimeoutError())
        self.objects.inject('PUT', BASE + 'delivery-task-private.json', 'before', TimeoutError())
        result = self.run_delivery()
        self.assertTrue(result['sent'])
        self.assertEqual(self.api.backend['sends'], 1)
        self.assertIn('tasks/get', [c[0] for c in self.api.calls])
        self.assertEqual(self.objects.get_json(COMPLETE)['report_identity'], d.report_identity(self.pointer))

    def test_snapshot_failure_does_not_skip_real_ack_gate(self):
        self.seed_claim()
        self.objects.inject('PUT', BASE + 'delivery-task-private.json', 'before', TimeoutError())
        with patch.object(d, 'verify_send', wraps=d.verify_send) as verify:
            self.assertTrue(self.recover()['sent'])
        self.assertGreater(verify.call_count, 0)
        self.assert_no_resend()

    def test_completion_put_retries_only_conditionally_with_frozen_bytes(self):
        self.seed_claim()
        self.objects.inject('PUT', COMPLETE, 'before', TimeoutError())
        self.assertTrue(self.recover()['sent'])
        puts = [c for c in self.objects.calls if c[:2] == ('PUT', COMPLETE)]
        self.assertEqual(len(puts), 2)
        self.assertEqual(puts[0][2], puts[1][2])
        self.assertTrue(all(c[3]['if-none-match'] == '*' for c in puts))
        self.assert_no_resend()

    def test_completion_put_success_get_timeout_reconciles_same_value(self):
        self.seed_claim()
        self.objects.inject('PUT', COMPLETE, 'after', lambda obj: obj.inject('GET', COMPLETE, 'before', TimeoutError()))
        self.assertTrue(self.recover()['sent'])
        puts = [c for c in self.objects.calls if c[:2] == ('PUT', COMPLETE)]
        self.assertEqual(len(puts), 2)
        self.assertEqual(puts[0][2], puts[1][2])
        self.assertTrue(all(c[3]['if-none-match'] == '*' for c in puts))
        self.assert_no_resend()

    def test_native_pointer_put_or_readback_timeout_does_not_reupload(self):
        for stage in ('before', 'after'):
            with self.subTest(stage=stage):
                self.fresh(); self.seed_claim()
                if stage == 'before':
                    self.objects.inject('PUT', NATIVE, 'before', TimeoutError())
                else:
                    self.objects.inject('PUT', NATIVE, 'after', lambda obj: obj.inject('GET', NATIVE, 'before', TimeoutError()))
                self.assertTrue(self.recover()['sent'])
                self.assertEqual(self.api.backend['uploads'], 1)
                self.assert_no_resend()

    def test_unknown_native_upload_is_discovered_read_only(self):
        self.seed_claim()
        self.api.faults['upload-after'].append(TimeoutError())
        self.assertTrue(self.recover()['sent'])
        self.assertEqual(self.api.backend['uploads'], 1)
        self.assert_no_resend()

    def test_crash_after_original_claim_never_grants_submission_again(self):
        self.objects.inject('PUT', CLAIM, 'after', Crash())
        with self.assertRaises(Crash): self.run_delivery()
        self.assertIn(CLAIM, self.objects.values)
        self.api.backend['task'] = dict(id=self.objects.get_json(CLAIM)['task_id'], status=dict(state='unknown'))
        self.api = FakeAPI(self.objects, self.api.backend)
        with self.assertRaisesRegex(ValueError, 'read_original_task_only'): self.recover()
        self.assert_no_resend()

    def test_crash_after_send_completion_put_recovers_original_report_identity(self):
        self.objects.inject('PUT', COMPLETE, 'after', Crash())
        with self.assertRaises(Crash): self.run_delivery()
        original = self.objects.values[COMPLETE]
        self.api = FakeAPI(self.objects, self.api.backend)
        self.assertEqual(self.recover()['status'], 'already_sent')
        self.assertEqual(self.objects.values[COMPLETE], original)
        self.assertEqual(self.objects.get_json(COMPLETE)['report_identity'], d.report_identity(self.pointer))
        self.assertEqual(self.api.backend['sends'], 1)
        self.assertNotIn('message/send', [c[0] for c in self.api.calls])

    def test_crash_after_native_upload_recovers_catalog_file_without_uploading_again(self):
        self.seed_claim()
        self.api.faults['upload-after'].append(Crash())
        with self.assertRaises(Crash): self.recover()
        self.api = FakeAPI(self.objects, self.api.backend)
        self.assertTrue(self.recover()['sent'])
        self.assertEqual(self.api.backend['uploads'], 1)
        self.assert_no_resend()

    def test_unknown_upload_with_no_visible_file_stays_bounded_and_never_reuploads(self):
        self.seed_claim()
        self.api.faults['upload-before'].append(TimeoutError())
        with self.assertRaisesRegex(ValueError, 'read_original_task_only'): self.recover()
        self.assertLessEqual(self.clock.elapsed, 12)
        self.assertEqual(self.api.backend['uploads'], 1)
        self.api = FakeAPI(self.objects, self.api.backend)
        with self.assertRaisesRegex(ValueError, 'read_original_task_only'): self.recover()
        self.assertEqual(self.api.backend['uploads'], 1)
        self.assert_no_resend()

    def test_original_task_read_timeout_recovers_without_submit(self):
        self.seed_claim()
        self.api.faults['tasks/get'].extend([TimeoutError(), RuntimeError('moi_http_503')])
        self.assertTrue(self.recover()['sent'])
        self.assert_no_resend()

    def test_initial_completion_get_timeout_after_restart_is_retried(self):
        self.seed_complete()
        self.objects.inject('GET', COMPLETE, 'before', TimeoutError())
        self.assertEqual(self.recover()['status'], 'already_sent')
        self.assert_no_resend()

    def test_persistent_receipt_failure_exhausts_one_shared_deadline(self):
        self.seed_claim()
        self.objects.faults['PUT', COMPLETE, 'before'].extend([TimeoutError() for _ in range(30)])
        with self.assertRaisesRegex(ValueError, 'read_original_task_only'): self.recover()
        self.assertEqual(self.clock.elapsed, 12)
        self.assert_no_resend()

    def test_snapshot_and_receipt_io_share_budget_without_late_mutations(self):
        self.seed_claim()
        def eat_budget(obj):
            self.clock.elapsed += 12
            raise TimeoutError()
        self.objects.inject('PUT', BASE + 'delivery-task-private.json', 'before', eat_budget)
        with self.assertRaisesRegex(ValueError, 'read_original_task_only'): self.recover()
        self.assertNotIn(COMPLETE, self.objects.values)
        self.assert_no_resend()

    def test_nontransient_auth_failure_stops_without_polling_or_mutation(self):
        self.seed_claim()
        self.objects.inject('PUT', COMPLETE, 'before', RuntimeError('minio_http_403'))
        with self.assertRaisesRegex(RuntimeError, '403'): self.recover()
        self.assertEqual(self.clock.sleeps, [])
        self.assert_no_resend()

    def test_real_ack_identity_and_duplicate_calls_remain_blocking(self):
        def wrong_day(task): task['events'][1]['output']['created_at'] = '2026-10-27T06:00:00Z'
        def wrong_body(task): task['events'][0]['arguments']['content'] += 'changed'
        def wrong_group(task): task['events'][0]['arguments']['channel_instance_id'] = 'other'
        def duplicate(task): task['events'].append(dict(task['events'][0], callId='second'))
        def reused_id(task):
            event = copy.deepcopy(task['events'][0]); event['arguments']['content'] = 'other'; task['events'].append(event)
        def wrong_task(task): task['id'] = 'other'
        def fake_ok(task): task['events'][1]['output'] = dict(ok=True)
        for change in (wrong_day, wrong_body, wrong_group, duplicate, reused_id, wrong_task, fake_ok):
            with self.subTest(change=change.__name__):
                self.fresh(); self.seed_claim(); change(self.api.backend['task'])
                with self.assertRaises(ValueError): self.recover()
                self.assertNotIn(COMPLETE, self.objects.values)
                self.assert_no_resend()

    def test_conflicting_completion_never_overwrites_or_weakens_ack_gate(self):
        for field, value in [('date', '2026-10-27'), ('sent', False), ('status', 'uncertain'),
                             ('channel_instance_id', 'other'), ('content', 'changed'), ('scope', 'one'),
                             ('publication_file_id', 'other'), ('prefix', 'other'), ('task_id', 'other'),
                             ('tool_call_id', 'other'), ('tool_output', dict(ok=True)), ('report_identity', {})]:
            with self.subTest(field=field):
                self.fresh(); final = self.seed_complete(native=False); final[field] = value
                self.objects.put_json(COMPLETE, final); raw = self.objects.values[COMPLETE]
                with self.assertRaisesRegex(ValueError, 'completion_conflict'): self.recover()
                self.assertEqual(self.objects.values[COMPLETE], raw)
                self.assertFalse(any(c[0] == 'PUT' for c in self.objects.calls))
                self.assert_no_resend()

    def test_legacy_claim_is_upgraded_after_task_verification_without_report_download(self):
        self.seed_claim(legacy=True)
        self.assertTrue(self.recover()['sent'])
        self.assertEqual(self.objects.get_json(COMPLETE)['report_identity'], d.report_identity(self.pointer))
        task_index = next(i for i, c in enumerate(self.api.calls) if c[0] == 'tasks/get')
        self.assertEqual(task_index, 0)
        self.assertEqual(self.recover()['status'], 'already_sent')
        self.assert_no_resend()

    def test_existing_complete_with_native_receipt_is_entirely_read_only(self):
        self.seed_complete()
        self.assertEqual(self.recover()['status'], 'already_sent')
        self.assertTrue(all(c[0] == 'GET' for c in self.objects.calls))
        self.assertNotIn('upload', [c[0] for c in self.api.calls])
        self.assert_no_resend()

    def test_corrupt_native_receipt_is_not_replaced(self):
        self.seed_complete()
        raw = b'wrong receipt'
        self.api.backend['files']['wrong'] = raw
        self.objects.put_json(NATIVE, dict(file_id='wrong', bytes=len(raw), sha256=d.sha(raw)))
        with self.assertRaisesRegex(ValueError, 'native_receipt_mismatch'): self.recover()
        self.assertTrue(all(c[0] == 'GET' for c in self.objects.calls))
        self.assert_no_resend()

    def test_atomic_claim_put_or_get_timeout_does_not_grant_send_permission(self):
        for stage in ('before', 'after'):
            with self.subTest(stage=stage):
                self.fresh()
                if stage == 'before':
                    self.objects.inject('PUT', CLAIM, 'after', TimeoutError())
                else:
                    self.objects.inject('PUT', CLAIM, 'after', lambda obj: obj.inject('GET', CLAIM, 'before', TimeoutError()))
                with self.assertRaises(TimeoutError): self.run_delivery()
                self.assert_no_resend()
                self.assertEqual(len([c for c in self.objects.calls if c[:2] == ('PUT', CLAIM)]), 1)

    def test_native_upload_intent_confirmation_timeout_recovers_without_deadlock(self):
        self.seed_claim()
        self.objects.inject('PUT', UPLOAD_CLAIM, 'after', lambda obj: obj.inject('GET', UPLOAD_CLAIM, 'before', TimeoutError()))
        self.assertTrue(self.recover()['sent'])
        self.assertEqual(self.api.backend['uploads'], 1)
        self.assert_no_resend()

    def test_concurrent_claim_winner_is_never_overwritten_or_submitted_by_loser(self):
        def other_wins(obj):
            winning_claim = json.loads(obj.calls[-1][2])
            winning_claim['owner'] = 'other-process'
            obj.put_json(CLAIM, winning_claim)
            self.api.backend['task'] = self.api.make_task(winning_claim)
        self.objects.inject('PUT', CLAIM, 'before', other_wins)
        self.assertTrue(self.run_delivery()['sent'])
        self.assertEqual(self.objects.get_json(CLAIM)['owner'], 'other-process')
        self.assert_no_resend()

    def test_legacy_enriched_completion_survives_restart_at_put_boundary(self):
        self.seed_claim(legacy=True)
        self.objects.inject('PUT', COMPLETE, 'after', Crash())
        with self.assertRaises(Crash): self.recover()
        self.api = FakeAPI(self.objects, self.api.backend)
        self.assertEqual(self.recover()['status'], 'already_sent')
        self.assertEqual(self.objects.get_json(COMPLETE)['report_identity'], d.report_identity(self.pointer))
        self.assert_no_resend()

    def test_changed_ready_report_identity_blocks_before_claim(self):
        self.bundle['root']['commits'] = dict(self.pointer['commits'], taas='changed')
        with self.assertRaisesRegex(ValueError, 'pointer_changed'): self.run_delivery()
        self.assertNotIn(CLAIM, self.objects.values)
        self.assert_no_resend()

    def test_runtime_terminal_and_malformed_states_are_not_retryable(self):
        for state in ('failed', 'input-required', 'auth-required', 'rejected', 'canceled', 'cancelled', 'invalid', None):
            with self.subTest(state=state):
                self.fresh(); self.seed_claim()
                self.api.backend['task']['status']['state'] = state
                with self.assertRaisesRegex(ValueError, 'terminal_do_not_resend|state_invalid'): self.recover()
                self.assertEqual(self.clock.sleeps, [])
                self.assertNotIn(COMPLETE, self.objects.values)
                self.assert_no_resend()

    def test_main_prepares_at_0950_waits_then_claims_and_sends_once(self):
        self.fresh('2026-10-28T09:50:00+08:00')
        prepared = []
        def check(*args):
            prepared.append(self.clock.now(d.LOCAL))
            self.clock.elapsed += 30
            return self.bundle
        code, status = self.run_main(dict(MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T10:00:00+08:00',
                                         MATRIX_DELIVERY_DEADLINE_SECONDS='180'), check)
        self.assertEqual(code, 0); self.assertTrue(status['sent'])
        self.assertEqual(prepared[0].strftime('%H:%M'), '09:50')
        claim_put = next(c for c in self.objects.calls if c[:2] == ('PUT', CLAIM))
        send = next(c for c in self.api.calls if c[0] == 'message/send')
        self.assertEqual(claim_put[4], 600); self.assertEqual(send[2], 600)
        self.assertEqual(sum(self.clock.sleeps), 570)
        self.assertTrue(all(s <= 60 for s in self.clock.sleeps))

    def test_main_does_not_wait_twice_if_preparation_finished_after_target(self):
        self.fresh('2026-10-28T09:50:00+08:00')
        def check(*args): self.clock.elapsed += 601; return self.bundle
        code, status = self.run_main(dict(MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T02:00:00Z'), check)
        self.assertEqual(code, 0); self.assertTrue(status['sent']); self.assertEqual(self.clock.sleeps, [])

    def test_main_preview_never_waits_claims_uploads_or_sends(self):
        self.fresh('2026-10-28T09:50:00+08:00')
        code, status = self.run_main(dict(MATRIX_DELIVERY_PREVIEW='true', MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T10:00:00+08:00'))
        self.assertEqual(code, 0); self.assertEqual(status['status'], 'preview_passed')
        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(all(c[0] == 'GET' for c in self.objects.calls)); self.assert_no_resend()

    def test_main_without_not_before_preserves_ten_oclock_gate(self):
        self.fresh('2026-10-28T09:50:00+08:00')
        code, status = self.run_main()
        self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_before_ten_blocked')
        self.assertEqual(self.clock.sleeps, []); self.assert_no_resend()

    def test_main_rejects_naive_wrong_day_or_before_ten_schedule(self):
        for value in ('2026-10-28T10:00:00', '2026-10-27T10:00:00+08:00',
                      '2026-10-28T09:59:59+08:00', '2026-10-29T02:00:00Z', ''):
            with self.subTest(value=value):
                self.fresh('2026-10-28T09:50:00+08:00')
                code, status = self.run_main(dict(MATRIX_DELIVERY_NOT_BEFORE=value))
                self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_not_before_invalid')
                self.assertEqual(self.objects.calls, []); self.assert_no_resend()

    def test_main_existing_claim_recovers_before_ten_without_preparing_or_waiting(self):
        self.fresh('2026-10-28T09:50:00+08:00'); self.seed_claim()
        def no_report(*args): raise AssertionError('no large report reads')
        code, status = self.run_main(dict(MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T10:00:00+08:00'), no_report)
        self.assertEqual(code, 0); self.assertTrue(status['sent'])
        self.assertEqual(self.clock.sleeps, []); self.assert_no_resend()

    def test_main_existing_completion_returns_already_sent_read_only_before_ten(self):
        self.seed_complete(); self.clock.origin = REAL_DATETIME.fromisoformat('2026-10-28T09:50:00+08:00')
        def no_report(*args): raise AssertionError('no large report reads')
        code, status = self.run_main(check=no_report)
        self.assertEqual(code, 0); self.assertEqual(status['status'], 'already_sent')
        self.assertEqual(self.clock.sleeps, [])
        self.assertTrue(all(c[0] == 'GET' for c in self.objects.calls)); self.assert_no_resend()

    def test_old_completion_keeps_original_bytes_and_omits_new_identity_field(self):
        legacy_claim = self.seed_claim(legacy=True)
        self.seed_complete(legacy_claim)
        original = self.objects.values[COMPLETE]
        self.assertNotIn('report_identity', json.loads(original))
        self.clock.origin = REAL_DATETIME.fromisoformat('2026-10-28T09:50:00+08:00')
        def no_report(*args): raise AssertionError('old completion needs no report reads')
        code, status = self.run_main(dict(MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T10:00:00+08:00'), no_report)
        self.assertEqual(code, 0); self.assertEqual(status['status'], 'already_sent')
        self.assertEqual(self.objects.values[COMPLETE], original)
        self.assertTrue(all(c[0] == 'GET' for c in self.objects.calls))
        self.assertEqual(self.clock.sleeps, [])
        self.assert_no_resend()

    def test_fresh_send_response_with_wrong_task_id_is_not_caught_as_uncertain(self):
        def wrong_id(): self.api.backend['task']['id'] = 'wrong-task'
        self.api.faults['message/send'].append(wrong_id)
        with self.assertRaisesRegex(ValueError, 'runtime_identity_changed'): self.run_delivery()
        self.assertEqual(self.api.backend['sends'], 1)
        self.assertNotIn('tasks/get', [c[0] for c in self.api.calls])
        self.assertNotIn(BASE + 'submission-uncertain.json', self.objects.values)
        self.assertNotIn(COMPLETE, self.objects.values)

    def test_main_expected_date_mismatch_takes_precedence_over_invalid_schedule(self):
        code, status = self.run_main(dict(MATRIX_EXPECTED_REPORT_DATE='2026-10-27', MATRIX_DELIVERY_NOT_BEFORE='bad'))
        self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_expected_date_mismatch')
        self.assertEqual(self.objects.calls, []); self.assertEqual(self.api.calls, [])

    def test_main_rechecks_date_after_preparation_and_immediately_before_send(self):
        self.fresh('2026-10-28T23:59:59+08:00')
        def after_midnight(*args): self.clock.elapsed += 2; return self.bundle
        code, status = self.run_main(check=after_midnight)
        self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_current_date_changed')
        self.assertNotIn(CLAIM, self.objects.values); self.assert_no_resend()
        self.fresh('2026-10-28T23:59:59+08:00')
        self.objects.inject('PUT', CLAIM, 'after', lambda obj: setattr(self.clock, 'elapsed', 2))
        code, status = self.run_main()
        self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_current_date_changed')
        self.assertIn(CLAIM, self.objects.values); self.assert_no_resend()

    def test_main_supervisor_budget_is_180_after_wait_and_default_is_900(self):
        for scheduled, budget in ((True, 180), (False, 900)):
            with self.subTest(scheduled=scheduled):
                self.fresh('2026-10-28T09:50:00+08:00' if scheduled else '2026-10-28T10:00:00+08:00')
                self.objects.faults['PUT', COMPLETE, 'before'].extend([TimeoutError() for _ in range(200)])
                env = dict(MATRIX_DELIVERY_NOT_BEFORE='2026-10-28T10:00:00+08:00', MATRIX_DELIVERY_DEADLINE_SECONDS='180') if scheduled else {}
                code, status = self.run_main(env)
                self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_uncertain_read_original_task_only')
                self.assertEqual(self.clock.elapsed, (600 if scheduled else 0) + budget)
                self.assertEqual(self.api.backend['sends'], 1)

    def test_main_rejects_invalid_deadline_values(self):
        for value in ('0', '-1', 'nan', 'inf', 'bad'):
            with self.subTest(value=value):
                self.fresh()
                code, status = self.run_main(dict(MATRIX_DELIVERY_DEADLINE_SECONDS=value))
                self.assertEqual(code, 1); self.assertEqual(status['safe_code'], 'delivery_deadline_invalid')
                self.assertEqual(self.objects.calls, []); self.assert_no_resend()


if __name__ == '__main__':
    unittest.main()
