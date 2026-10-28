"""Offline publication recovery through the real Objects.call retry layer."""

import http.client
import json
import unittest
import urllib.error
from unittest.mock import patch

import daily_delivery
import resilient_storage as storage


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeSignedObjects:
    """Accept PUT bytes before losing the response; script GET independently."""

    def __init__(self, clock, puts=(), gets=(), durations=()):
        self.clock = clock
        self.puts = list(puts)
        self.gets = list(gets)
        self.durations = list(durations)
        self.objects = {}
        self.requests = []

    def call(self, owner, method, key, raw=None, headers=None,
             response_limit=32 * 1024 * 1024, timeout=None, query=None):
        headers = dict(headers or {})
        self.requests.append(dict(method=method, key=key, raw=raw, headers=headers,
                                  response_limit=response_limit, timeout=timeout, query=query))
        if self.durations:
            self.clock.now += self.durations.pop(0)
        if method == 'PUT':
            if headers.get('if-none-match') == '*' and key in self.objects:
                raise RuntimeError('minio_http_412')
            accepted, error = self.puts.pop(0) if self.puts else (True, None)
            if accepted:
                self.objects[key] = raw
            if error is not None:
                raise error
            return 200, {}, b''
        if method != 'GET':
            raise AssertionError('unexpected_fake_method')
        if self.gets:
            result = self.gets.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        if key not in self.objects:
            raise RuntimeError('minio_http_404')
        return 200, {'Content-Type': 'application/json',
                     'Content-Disposition': 'inline'}, self.objects[key]

    def methods(self):
        return [request['method'] for request in self.requests]


class StorageRecoveryTests(unittest.TestCase):
    key = 'private/checkpoint.json'
    raw = b'{"checkpoint":"accepted"}'

    def setUp(self):
        self.clock = FakeClock()
        self.events = []
        self.enter_patch('resilient_storage.time.monotonic', self.clock.monotonic)
        self.enter_patch('resilient_storage.time.sleep', self.clock.sleep)
        self.enter_patch('resilient_storage.emit', self.record_event)
        self.enter_patch('pipeline_telemetry.emit', self.record_event)
        self.enter_patch('socket.socket.connect', side_effect=AssertionError('network_forbidden'))
        self.enter_patch('socket.create_connection', side_effect=AssertionError('network_forbidden'))
        self.enter_patch('resilient_storage.SignedObjects.call', autospec=True,
                         side_effect=lambda *args, **kwargs: self.fake.call(*args, **kwargs))

    def enter_patch(self, target, *args, **kwargs):
        patcher = patch(target, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def record_event(self, kind, **fields):
        self.events.append(dict(kind=kind, **fields))

    def store(self, **kwargs):
        fake = FakeSignedObjects(self.clock, **kwargs)
        store = storage.Objects(dict(endpoint=storage.EXPECTED_ENDPOINT,
                                     bucket_name=storage.EXPECTED_BUCKET,
                                     access_key_id='fake-access', access_key_secret='fake-secret'))
        self.fake = fake
        return store, fake

    def publish(self, store):
        return store.publish(self.key, self.raw, 'application/json')

    def test_success_preserves_verified_result_and_headers(self):
        store, fake = self.store()
        self.assertEqual(self.publish(store), dict(
            key=self.key, bytes=len(self.raw), sha256=storage.sha256(self.raw),
            readback_verified=True, content_type='application/json', content_disposition='inline'))
        self.assertEqual(fake.methods(), ['PUT', 'GET'])
        self.assertEqual(fake.requests[0]['headers'], {
            'content-type': 'application/json', 'content-disposition': 'inline',
            'cache-control': 'private, max-age=300', 'x-amz-meta-sha256': storage.sha256(self.raw)})
        self.assertFalse(self.clock.sleeps)

    def test_one_to_three_get_timeouts_reobserve_without_another_put(self):
        for lost_put in (False, True):
            for failures in (1, 2, 3):
                with self.subTest(lost_put=lost_put, failures=failures):
                    store, fake = self.store(
                        puts=[(True, TimeoutError('lost_put'))] if lost_put else (),
                        gets=[TimeoutError('lost_get') for _ in range(failures)])
                    self.assertTrue(self.publish(store)['readback_verified'])
                    self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * (failures + 1))

    def test_transient_read_errors_do_not_republish(self):
        errors = [ConnectionError(), urllib.error.URLError(TimeoutError()),
                  http.client.IncompleteRead(b'partial', 10)]
        errors += [RuntimeError('minio_http_' + str(code)) for code in (429, 500, 502, 503, 504)]
        for error in errors:
            with self.subTest(error=type(error).__name__, code=str(error)):
                store, fake = self.store(gets=[error] * 3)
                self.assertTrue(self.publish(store)['readback_verified'])
                self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * 4)

    def test_uncertain_put_http_response_is_reconciled_before_retry(self):
        for code in (429, 500, 502, 503, 504):
            with self.subTest(code=code):
                store, fake = self.store(puts=[(True, RuntimeError('minio_http_' + str(code)))],
                                         gets=[TimeoutError()] * 3)
                self.assertTrue(self.publish(store)['readback_verified'])
                self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * 4)

    def test_permanent_get_timeout_has_one_put_and_a_fixed_read_limit(self):
        for lost_put in (False, True):
            with self.subTest(lost_put=lost_put):
                self.clock.sleeps.clear()
                store, fake = self.store(
                    puts=[(True, TimeoutError())] if lost_put else (), gets=[TimeoutError()] * 30)
                with self.assertRaises(TimeoutError):
                    self.publish(store)
                self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * storage.PUBLISH_MAX_READS)
                self.assertEqual(len(self.clock.sleeps), storage.PUBLISH_MAX_READS - 1)
                self.assertLessEqual(sum(self.clock.sleeps), storage.PUBLISH_BUDGET_SECONDS)
                self.assertTrue(self.events[-1]['kind'].endswith('exhausted'))

    def test_permanent_get_503_keeps_original_error_and_fixed_read_limit(self):
        store, fake = self.store(gets=[RuntimeError('minio_http_503')] * 30)
        with self.assertRaisesRegex(RuntimeError, '^minio_http_503$'):
            self.publish(store)
        self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * storage.PUBLISH_MAX_READS)

    def test_real_404_allows_only_identical_bounded_puts(self):
        store, fake = self.store(puts=[(False, TimeoutError())] * 30)
        with self.assertRaisesRegex(ValueError, 'readback_mismatch'):
            self.publish(store)
        self.assertEqual(fake.methods(), ['PUT', 'GET'] * storage.PUBLISH_MAX_PUTS)
        writes = [request for request in fake.requests if request['method'] == 'PUT']
        self.assertTrue(all(request['raw'] == self.raw for request in writes))
        self.assertTrue(all(request['headers'] == writes[0]['headers'] for request in writes))
        self.assertEqual(len(self.clock.sleeps), storage.PUBLISH_MAX_PUTS - 1)

    def test_404_then_same_bytes_put_can_succeed(self):
        store, fake = self.store(puts=[(False, TimeoutError()), (False, TimeoutError())])
        self.assertTrue(self.publish(store)['readback_verified'])
        self.assertEqual(fake.methods(), ['PUT', 'GET'] * 3)

    def test_timeout_then_404_then_timeout_shares_the_same_observation_budget(self):
        store, fake = self.store(gets=[TimeoutError(), RuntimeError('minio_http_404')]
                                 + [TimeoutError()] * 3)
        self.assertTrue(self.publish(store)['readback_verified'])
        self.assertEqual(fake.methods(), ['PUT', 'GET', 'GET', 'PUT'] + ['GET'] * 4)

    def test_404_and_transient_cycles_cannot_reset_read_limit(self):
        store, fake = self.store(gets=[TimeoutError(), RuntimeError('minio_http_404')]
                                 + [TimeoutError()] * 30)
        with self.assertRaises(TimeoutError):
            self.publish(store)
        self.assertEqual(fake.methods().count('PUT'), 2)
        self.assertEqual(fake.methods().count('GET'), storage.PUBLISH_MAX_READS)

    def test_deadline_shrinks_request_timeouts_and_is_not_reset_by_404(self):
        store, fake = self.store(gets=[RuntimeError('minio_http_404'), TimeoutError()],
                                 durations=[1, 1, 1, 1])
        with patch.object(storage, 'PUBLISH_BUDGET_SECONDS', 5):
            with self.assertRaisesRegex(TimeoutError, 'publish_deadline_exceeded'):
                self.publish(store)
        self.assertEqual(fake.methods(), ['PUT', 'GET', 'PUT', 'GET'])
        self.assertEqual([request['timeout'] for request in fake.requests], [5, 4, 2, 1])
        self.assertEqual(self.clock.now, 105)
        self.assertEqual(self.clock.sleeps, [1])

    def test_wrong_size_or_hash_fails_immediately_without_repairing_evidence(self):
        for received in (b'short', self.raw + b'extra', b'x' * len(self.raw)):
            for failures in (0, 3):
                with self.subTest(size=len(received), failures=failures):
                    store, fake = self.store(gets=[TimeoutError()] * failures + [
                        (200, {'X-Amz-Meta-Sha256': storage.sha256(self.raw)}, received),
                        (200, {}, self.raw)])
                    with self.assertRaisesRegex(ValueError, 'readback_mismatch'):
                        self.publish(store)
                    self.assertEqual(fake.methods(), ['PUT'] + ['GET'] * (failures + 1))
                    self.assertEqual(len(fake.gets), 1)

    def test_unexpected_read_status_cannot_verify_matching_bytes(self):
        store, fake = self.store(gets=[(206, {}, self.raw)])
        with self.assertRaisesRegex(ValueError, 'readback_mismatch'):
            self.publish(store)
        self.assertEqual(fake.methods(), ['PUT', 'GET'])

    def test_403_412_and_other_permanent_errors_never_retry(self):
        for code in (400, 403, 412, 501):
            for method in ('PUT', 'GET'):
                with self.subTest(code=code, method=method):
                    error = RuntimeError('minio_http_' + str(code))
                    store, fake = self.store(**({'puts': [(False, error)]} if method == 'PUT'
                                               else {'gets': [error]}))
                    with self.assertRaisesRegex(RuntimeError, '^minio_http_' + str(code) + '$'):
                        self.publish(store)
                    self.assertEqual(fake.methods(), ['PUT'] if method == 'PUT' else ['PUT', 'GET'])

    def test_recovery_telemetry_has_no_payload_key_url_or_exception_message(self):
        private = 'fake-secret https://private.invalid/?X-Amz-Signature=hidden'
        store, fake = self.store(puts=[(True, TimeoutError(private))], gets=[TimeoutError(private)])
        store.publish(private, private.encode(), 'application/json')
        serialized = json.dumps(self.events)
        for secret in ('fake-secret', 'private.invalid', 'X-Amz-Signature', 'hidden', 'fake-access'):
            self.assertNotIn(secret, serialized)
        self.assertIn('artifact_put_uncertain', serialized)
        self.assertIn('artifact_readback_retry', serialized)
        self.assertEqual(fake.methods(), ['PUT', 'GET', 'GET'])

    def test_atomic_claim_412_only_reads_winner_and_never_uses_publish(self):
        store, fake = self.store()
        winner = {'owner': 'first'}
        fake.objects[self.key] = daily_delivery.json_bytes(winner)
        with patch.object(store, 'publish', side_effect=AssertionError('claim_used_publish')):
            self.assertEqual(daily_delivery.create_once(store, self.key, {'owner': 'second'}),
                             (False, winner))
        self.assertEqual(fake.methods(), ['PUT', 'GET'])
        self.assertEqual(fake.requests[0]['headers']['if-none-match'], '*')
        self.assertEqual(fake.objects[self.key], daily_delivery.json_bytes(winner))

    def test_atomic_claim_uncertainty_or_http_error_never_retries_or_grants_claim(self):
        for error in (TimeoutError(), RuntimeError('minio_http_503'), RuntimeError('minio_http_403')):
            with self.subTest(error=type(error).__name__, code=str(error)):
                store, fake = self.store(puts=[(True, error)])
                with patch.object(store, 'publish', side_effect=AssertionError('claim_used_publish')):
                    with self.assertRaises(type(error)):
                        daily_delivery.create_once(store, self.key, {'owner': 'first'})
                self.assertEqual(fake.methods(), ['PUT'])
                self.assertEqual(fake.requests[0]['headers']['if-none-match'], '*')

    def test_atomic_claim_readback_timeout_never_repeats_conditional_put(self):
        store, fake = self.store(gets=[TimeoutError()] * 30)
        with patch.object(store, 'publish', side_effect=AssertionError('claim_used_publish')):
            with self.assertRaises(TimeoutError):
                daily_delivery.create_once(store, self.key, {'owner': 'first'})
        self.assertEqual(fake.methods(), ['PUT', 'GET', 'GET', 'GET'])
        self.assertEqual(fake.requests[0]['headers']['if-none-match'], '*')


if __name__ == '__main__':
    unittest.main()
