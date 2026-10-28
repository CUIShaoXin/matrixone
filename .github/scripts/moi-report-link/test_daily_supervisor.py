import datetime as dt
import tempfile
import unittest
from pathlib import Path

import daily_supervisor as s


class Clock:
    def __init__(self, hour=4, minute=17):
        self.at = dt.datetime(2026, 10, 29, hour, minute, tzinfo=s.LOCAL)
        self.elapsed = 0

    def now(self): return self.at
    def mono(self): return self.elapsed
    def sleep(self, seconds):
        self.elapsed += seconds
        self.at += dt.timedelta(seconds=seconds)


class SupervisorTests(unittest.TestCase):
    def run_supervisor(self, kind, runner, clock=None, scheduled=False):
        clock = clock or Clock()
        with tempfile.TemporaryDirectory() as tmp:
            return s.supervise(kind, scheduled, {'GITHUB_RUN_ID': '123'}, clock.now,
                               clock.sleep, clock.mono, runner, Path(tmp))

    def test_scan_recovery_uses_same_explicit_batch(self):
        envs = []
        def run(kind, env, timeout, out):
            envs.append(env.copy())
            return {'status': 'failed', 'error_type': 'TimeoutError'} if len(envs) == 1 else {'status': 'passed'}
        self.assertEqual(self.run_supervisor('scan', run, scheduled=True)['attempts'], 2)
        self.assertEqual([e['MATRIX_PIPELINE_RESUME_RUN_ID'] for e in envs], ['daily-20261029'] * 2)
        self.assertTrue(all(e['MATRIX_EXPECTED_REPORT_DATE'] == '2026-10-29' for e in envs))

    def test_identity_failure_is_not_retried(self):
        calls = []
        def run(*args):
            calls.append(1); return {'status': 'failed', 'safe_code': 'delivery_claim_conflict'}
        self.assertEqual(self.run_supervisor('deliver', run)['status'], 'failed')
        self.assertEqual(len(calls), 1)

    def test_persistent_network_failure_is_bounded(self):
        def run(*args): return {'status': 'failed', 'error_type': 'TimeoutError'}
        self.assertEqual(self.run_supervisor('scan', run)['attempts'], 3)
        self.assertEqual(self.run_supervisor('deliver', run)['attempts'], 5)

    def test_warmup_verifies_before_ten_but_supplies_send_barrier(self):
        clock = Clock(); observed = []
        def run(kind, env, timeout, out):
            observed.append((clock.now(), env.copy(), timeout))
            return {'status': 'sent_verified'}
        self.run_supervisor('deliver', run, clock, scheduled=True)
        at, env, timeout = observed[0]
        self.assertEqual((at.hour, at.minute), (9, 50))
        self.assertEqual(env['MATRIX_DELIVERY_NOT_BEFORE'], '2026-10-29T10:00:00+08:00')
        self.assertEqual(env['MATRIX_DELIVERY_DEADLINE_SECONDS'], '180')
        self.assertEqual(timeout, 1500)

    def test_late_scheduler_does_not_wait_for_another_day(self):
        clock = Clock(10, 3)
        def run(*args): return {'status': 'already_sent'}
        self.assertEqual(self.run_supervisor('deliver', run, clock, True)['seconds'], 0)

    def test_scheduled_ready_poll_keeps_waiting_through_warmup(self):
        clock = Clock(9, 50); calls = []
        def run(*args):
            calls.append(clock.now())
            return ({'status': 'failed', 'safe_code': 'minio_http_404'}
                    if clock.now().hour < 10 else {'status': 'sent_verified'})
        final = self.run_supervisor('deliver', run, clock, True)
        self.assertEqual(final['status'], 'passed')
        self.assertEqual(len(calls), 21)
        self.assertEqual(calls[-1].hour, 10)

    def test_midnight_stops_recovery_instead_of_using_new_date(self):
        clock = Clock(23, 59)
        def run(*args):
            clock.sleep(70)
            return {'status': 'failed', 'error_type': 'TimeoutError'}
        with self.assertRaisesRegex(ValueError, 'supervisor_date_changed'):
            self.run_supervisor('deliver', run, clock)


if __name__ == '__main__': unittest.main()
