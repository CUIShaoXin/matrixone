"""Bounded same-batch recovery and early delivery warmup on the cloud runner."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from pipeline_telemetry import emit, error_fields

LOCAL = dt.timezone(dt.timedelta(hours=8))
TRANSIENT_TYPES = {'TimeoutError', 'URLError', 'ConnectionError', 'IncompleteRead',
                   'ConnectionResetError', 'RemoteDisconnected'}
SCAN_RECOVERABLE = {'component_scan_incomplete', 'source_review_incomplete',
                    'knowledge_ingestion_deadline', 'moi_workflow_timeout'}
DELIVERY_RECOVERABLE = {'delivery_uncertain_read_original_task_only',
                        'minio_http_404'}


def local_now():
    return dt.datetime.now(LOCAL)


def retryable(status, kind):
    if status.get('error_type') == 'HTTPError':
        return status.get('http_status') in (408, 429, 500, 502, 503, 504)
    if status.get('error_type') in TRANSIENT_TYPES or status.get('reason_type') in TRANSIENT_TYPES:
        return True
    code = status.get('safe_code', '')
    if code in (SCAN_RECOVERABLE if kind == 'scan' else DELIVERY_RECOVERABLE):
        return True
    return code in {prefix + str(n) for prefix in ('minio_http_', 'moi_http_', 'login_free_http_')
                    for n in (408, 429, 500, 502, 503, 504)}


def wait_until(target, date, now=local_now, sleep=time.sleep):
    while True:
        current = now()
        if current.astimezone(LOCAL).date().isoformat() != date:
            raise ValueError('supervisor_date_changed')
        seconds = (target - current).total_seconds()
        if seconds <= 0:
            return
        sleep(min(seconds, 30))


def invoke(kind, env, timeout, out):
    script = 'daily_pipeline.py' if kind == 'scan' else 'daily_delivery.py'
    status_file = Path('out') / ('pipeline' if kind == 'scan' else 'delivery') / 'status.json'
    # A killed child must not accidentally reuse the previous attempt's status.
    status_file.unlink(missing_ok=True)
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).with_name(script))],
                                env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'failed', 'error_type': 'TimeoutError',
                'safe_code': 'supervisor_child_deadline'}
    if not status_file.exists():
        return {'status': 'failed', 'error_type': 'RuntimeError',
                'safe_code': 'supervisor_child_status_missing', 'exit_code': result.returncode}
    value = json.loads(status_file.read_text())
    if result.returncode != 0 and value.get('status') != 'failed':
        raise ValueError('supervisor_exit_status_conflict')
    return value


def supervise(kind, scheduled=False, env=None, now=local_now, sleep=time.sleep,
              monotonic=time.monotonic, run=invoke, out=Path('out/supervisor')):
    env = dict(os.environ if env is None else env)
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    date = now().astimezone(LOCAL).date().isoformat()
    env['MATRIX_EXPECTED_REPORT_DATE'] = date
    if kind == 'scan':
        env['MATRIX_PIPELINE_RESUME_RUN_ID'] = env.get('MATRIX_PIPELINE_RESUME_RUN_ID') or (
            'daily-' + date.replace('-', '') if scheduled else
            env['GITHUB_RUN_ID'] + '-' + env.get('GITHUB_RUN_ATTEMPT', '1'))
        budget, max_attempts = 270 * 60, 3
    else:
        budget, max_attempts = 15 * 60, 5
        if scheduled:
            # Before 10:00 a missing ready pointer is an observation, not a
            # failed send. Allow bounded read-only polls through the warmup.
            # 20 warmup polls plus 30 post-release polls, with a final read at
            # the boundary. The shared deadline remains authoritative.
            max_attempts = 51
            target = dt.datetime.combine(dt.date.fromisoformat(date), dt.time(10), LOCAL)
            warmup = target - dt.timedelta(minutes=10)
            emit('delivery_warmup_wait', date=date, verify_at_beijing=warmup.isoformat(),
                 send_not_before_beijing=target.isoformat())
            wait_until(warmup, date, now, sleep)
            env['MATRIX_DELIVERY_NOT_BEFORE'] = target.isoformat()
            # Waiting until 10:00 is outside the bounded recovery budget.
            budget += max(0, (target - now()).total_seconds())
        env['MATRIX_DELIVERY_DEADLINE_SECONDS'] = '180'
    start = monotonic(); attempts = []
    for attempt in range(1, max_attempts + 1):
        if now().astimezone(LOCAL).date().isoformat() != date:
            raise ValueError('supervisor_date_changed')
        remaining = budget - (monotonic() - start)
        if remaining <= 0:
            break
        emit('supervisor_attempt', phase=kind, attempt=attempt, same_batch=True,
             seconds_remaining=round(remaining, 3))
        status = run(kind, env, remaining, out)
        attempts.append(status)
        (out / (kind + '-attempt-' + str(attempt) + '.json')).write_text(json.dumps(status))
        if status.get('status') in ('passed', 'preview_passed', 'already_sent', 'sent_verified'):
            final = dict(status='passed', phase=kind, date=date, attempts=len(attempts),
                         child_status=status['status'], same_batch=True,
                         seconds=round(monotonic()-start, 3))
            (out / (kind + '-status.json')).write_text(json.dumps(final)); return final
        if not retryable(status, kind):
            break
        remaining = budget - (monotonic() - start)
        if attempt < max_attempts and remaining > 0:
            sleep(min(30, remaining))
    final = dict(status='failed', phase=kind, date=date, attempts=len(attempts),
                 same_batch=True, seconds=round(monotonic()-start, 3))
    if attempts:
        for key in ('safe_code', 'error_type', 'reason_type', 'http_status'):
            if key in attempts[-1]: final[key] = attempts[-1][key]
    (out / (kind + '-status.json')).write_text(json.dumps(final)); return final


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=('scan', 'deliver'))
    parser.add_argument('--scheduled', action='store_true')
    args = parser.parse_args()
    try:
        status = supervise(args.kind, scheduled=args.scheduled)
    except Exception as exc:
        status = dict(status='failed', phase=args.kind, **error_fields(exc))
        if re.fullmatch('[a-z][a-z0-9_]{0,100}', str(exc)):
            status['safe_code'] = str(exc)
        out = Path('out/supervisor'); out.mkdir(parents=True, exist_ok=True)
        (out / (args.kind + '-status.json')).write_text(json.dumps(status))
    print(json.dumps(status), flush=True)
    return 0 if status['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
