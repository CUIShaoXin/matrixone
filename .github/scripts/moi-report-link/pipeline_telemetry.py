"""Safe, durable stage timings. Payloads, URLs and exception messages stay private."""
import contextlib
import contextvars
import datetime as dt
import functools
import json
import os
from pathlib import Path
import threading
import time
import urllib.error

STAGE = contextvars.ContextVar('matrix_stage', default='pipeline')
LOCK = threading.RLock()


def error_fields(exc):
    result = {'error_type': type(exc).__name__}
    reason = getattr(exc, 'reason', None)
    if reason is not None:
        result['reason_type'] = type(reason).__name__
    if isinstance(exc, urllib.error.HTTPError):
        result['http_status'] = exc.code
    return result


def emit(kind, **fields):
    row = dict(kind=kind, stage=STAGE.get(), at_utc=dt.datetime.now(dt.timezone.utc).isoformat(), **fields)
    with LOCK:
        path = Path(os.environ.get('MATRIX_TIMINGS_FILE', 'out/pipeline-events.jsonl'))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as stream:
            stream.write(json.dumps(row) + '\n')
        print(json.dumps(row), flush=True)


@contextlib.contextmanager
def span(label, **fields):
    token = STAGE.set(label)
    start = time.monotonic()
    emit('stage_start', **fields)
    try:
        yield
    except BaseException as exc:
        emit('stage_end', status='failed', seconds=round(time.monotonic()-start, 3), **fields, **error_fields(exc))
        raise
    else:
        emit('stage_end', status='passed', seconds=round(time.monotonic()-start, 3), **fields)
    finally:
        STAGE.reset(token)


def timed(label):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            with span(label):
                return function(*args, **kwargs)
        return wrapped
    return decorate
