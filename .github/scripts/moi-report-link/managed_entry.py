"""MOI-dispatched entry. Reuses the accepted scan and delivery implementations."""
import json
import os
from pathlib import Path

from batch_context import BatchContext
from daily_pipeline import main as scan
from daily_delivery import deliver, check_bundle, compose
from cloud_daily import DailyAPI, json_bytes
from resilient_storage import Objects


def delivery(*, preview):
    ctx = BatchContext.from_env()
    api = DailyAPI(os.environ['MOI_API_KEY'])
    objects = Objects.from_workspace(api)
    if preview:
        # Test batches never publish the global production daily/ready.json.
        bundle = check_bundle(api, objects, ctx.prefix, ctx.business_date)
        content = compose(bundle, ctx.business_date)
        value = dict(status='preview_passed', sent=False, run_id=ctx.run_id,
                     publication_file_id=bundle['root']['publication_file_id'],
                     pages_verified=bundle['pages_verified'], message_bytes=len(content.encode()))
    else:
        # Existing sender owns the shared claim and actual acknowledgement.
        import datetime as dt
        from daily_delivery import LOCAL, require, read_json
        require(dt.datetime.now(LOCAL).date().isoformat() == ctx.business_date, 'production_delivery_wrong_day')
        import time
        out = Path('out/delivery'); out.mkdir(parents=True, exist_ok=True)
        while dt.datetime.now(LOCAL).hour < 10:
            (out/'status.json').write_bytes(json_bytes(dict(ctx.record(), status='waiting_for_delivery_time', sent=False)))
            time.sleep(15)
            require(dt.datetime.now(LOCAL).date().isoformat() == ctx.business_date, 'production_delivery_wrong_day')
        pointer = read_json(objects, 'daily/' + ctx.business_date.replace('-', '') + '/ready.json')
        require(pointer['run_id'] == ctx.run_id, 'delivery_requested_batch_mismatch')
        value = deliver(api, objects, ctx.business_date)
    out = Path('out/delivery'); out.mkdir(parents=True, exist_ok=True)
    (out/'status.json').write_bytes(json_bytes(dict(ctx.record(), **value)))
    return 0


def sync_status():
    from orchestration_status import sync
    ctx = BatchContext.from_env()
    api = DailyAPI(os.environ['MOI_API_KEY'])
    return sync(api, Objects.from_workspace(api), ctx)


def run(out=Path('out/orchestration')):
    ctx = BatchContext.from_env()
    out.mkdir(parents=True, exist_ok=True)
    status = dict(ctx.record(), status='running', sent=False)
    result = 1
    phase = 'scan'
    (out/'status.json').write_bytes(json_bytes(status))
    try:
        from contextlib import nullcontext
        from orchestration_status import StatusMonitor
        monitor = StatusMonitor(sync_status) if os.environ.get('MATRIX_STATUS_MONITOR') == 'true' else nullcontext()
        with monitor:
            result = scan()
            if result == 0:
                phase = 'delivery'
                result = delivery(preview=ctx.execution_mode == 'no_send')
        status['status'] = 'succeeded' if result == 0 else 'failed'
        if result != 0: status['failure_stage'] = phase
        delivery_status = Path('out/delivery/status.json')
        if delivery_status.exists():
            saved = json.loads(delivery_status.read_bytes())
            if saved.get('run_id') == ctx.run_id:
                status.update(sent=saved.get('sent', False), receipt_file_id=saved.get('receipt_file_id'))
    except Exception as exc:
        from pipeline_telemetry import error_fields
        import re
        status.update(status='failed', failure_stage=phase, sent=False if ctx.execution_mode=='no_send' or phase=='scan' else None, **error_fields(exc))
        if re.fullmatch(r'[a-z][a-z0-9_]{0,100}', str(exc)): status['safe_code'] = str(exc)
        result = 1
    finally:
        # Persist locally first; status replay is separate from business execution.
        (out/'status.json').write_bytes(json_bytes(status))
        try:
            status['moi_status'] = sync_status()
        except Exception as exc:
            status['moi_status'] = dict(synced=False, error_type=type(exc).__name__, replay_required=True)
            result = 1
        (out/'status.json').write_bytes(json_bytes(status))
    print(json.dumps(status), flush=True)
    return result


if __name__ == '__main__': raise SystemExit(run())
