"""Replayable MOI file snapshots; replay never starts a scan or sends a message."""
import datetime as dt
import hashlib
import json
from pathlib import Path

from cloud_daily import json_bytes
from daily_delivery import read_json

REPOSITORIES = (('matrixone', 'main'), ('taas', 'main'), ('matrixflow', 'dev'))


def snapshot(api, objects, ctx):
    value = dict(schema='matrix_orchestration_status_v1', **ctx.record(),
                 observed_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                 repositories={}, stages={}, status='waiting', sent=False)
    root = read_json(objects, ctx.prefix+'/checkpoint.json', missing=True) or {}
    for repo, branch in REPOSITORIES:
        key = 'receipts/'+ctx.business_date.replace('-', '')+'/acquisition-'+ctx.run_id+'/'+repo+'.json'
        state = read_json(objects, key, missing=True) or {}
        proof = state.get('proof', {})
        value['repositories'][repo] = dict(branch=branch, commit=state.get('commit'),
            zip_bytes=proof.get('bytes'), zip_sha256=proof.get('sha256'), minio_key=state.get('key'),
            stages=state.get('stages', {}), status=state.get('status', 'waiting'),
            attempts=state.get('attempts', 0), failure=state.get('failure'))
    events = Path('out/pipeline-events.jsonl')
    if events.exists():
        for line in events.read_text().splitlines():
            try: event = json.loads(line)
            except json.JSONDecodeError: continue  # A concurrent append may be incomplete.
            if event.get('kind') not in ('stage_start', 'stage_end'): continue
            name = event.get('stage')
            if name not in ('three_repository_acquisition', 'three_repository_component_scan',
                            'component_focus_summary', 'daily_delivery_readiness',
                            'code_repository', 'api_context_for', 'api_publish_report'): continue
            identity = name + (':'+event['repository'] if event.get('repository') else '')
            value['stages'][identity] = dict(status=event.get('status', 'running'),
                at_utc=event['at_utc'], error_type=event.get('error_type'))
    for name, path in (('scan', 'out/pipeline/status.json'), ('delivery', 'out/delivery/status.json'),
                       ('overall', 'out/orchestration/status.json')):
        source = Path(path)
        if not source.exists(): continue
        data = json.loads(source.read_bytes())
        if data.get('run_id') != ctx.run_id: continue
        value['stages'][name] = data
    reviews = read_json(objects, ctx.prefix+'/reviews/checkpoint.json', missing=True) or {}
    components = read_json(objects, ctx.prefix+'/components/checkpoint.json', missing=True) or {}
    for repo, _ in REPOSITORIES:
        target = value['repositories'][repo]
        for label, field in (('code_review', 'code_repositories'), ('api_port_review', 'repositories')):
            item = reviews.get(field, {}).get(repo, {})
            target['stages'][label] = 'succeeded' if item.get('accepted') else ('running' if item else 'waiting')
        item = components.get('repositories', {}).get(repo, {})
        target['stages']['component_scan'] = 'succeeded' if item.get('accepted') else ('running' if item else 'waiting')
        for failure in root.get('failures', []):
            if failure.get('repository') == repo and failure.get('stage') == 'components' and not item.get('accepted'):
                target['stages']['component_scan'] = 'failed'
        for failure in reviews.get('issues', []):
            for label, prefix in (('code_review', 'code_'), ('api_port_review', 'api_')):
                if failure.get('stage') == prefix+repo and target['stages'][label] != 'succeeded':
                    target['stages'][label] = 'failed'
    value['stages']['report'] = dict(status='succeeded' if root.get('published') else 'waiting')
    overall = value['stages'].get('overall', {})
    value['status'] = overall.get('status', 'running')
    delivery = value['stages'].get('delivery', {})
    value['sent'] = delivery.get('sent', overall.get('sent', False))
    value['delivery_receipt_file_id'] = delivery.get('receipt_file_id', overall.get('receipt_file_id'))
    value['failures'] = root.get('failures', []) + reviews.get('issues', [])
    value['executions'] = root.get('executions', [])
    value['retry_count'] = max(0, len(value['executions'])-1)
    if root.get('publication_file_id'):
        value['publication_file_id'] = root['publication_file_id']
        try:
            publication = json.loads(api.file(root['publication_file_id']))
            value['report_url'] = publication['url']
            value['report_expires_at_utc'] = publication['expires_at_utc']
            value['report_details'] = dict(status='succeeded')
        except Exception as exc:
            # Report enrichment must not destroy the durable status during a MOI outage.
            value['report_details'] = dict(status='pending', error_type=type(exc).__name__)
    return value


def sync(api, objects, ctx):
    value = snapshot(api, objects, ctx)
    key = ctx.prefix+'/orchestration/status.json'
    raw = json_bytes(value)
    # The complete status survives a MOI outage before upload is attempted.
    objects.publish(key, raw, 'application/json')
    return upload_saved(api, objects, ctx)


def upload_saved(api, objects, ctx):
    raw = objects.call('GET', ctx.prefix+'/orchestration/status.json')[2]
    value = json.loads(raw)
    if (value['run_id'], value['business_date']) != (ctx.run_id, ctx.business_date):
        raise ValueError('status_identity_mismatch')
    if value.get('report_details', {}).get('status') == 'pending':
        publication = json.loads(api.file(value['publication_file_id']))
        value['report_url'] = publication['url']
        value['report_expires_at_utc'] = publication['expires_at_utc']
        value['report_details'] = dict(status='succeeded')
        raw = json_bytes(value)
        objects.publish(ctx.prefix+'/orchestration/status.json', raw, 'application/json')
    digest = hashlib.sha256(raw).hexdigest()
    receipt_key = ctx.prefix+'/orchestration/sync-'+digest+'.json'
    saved = read_json(objects, receipt_key, missing=True)
    if saved is None:
        saved = api.upload('matrix-run-'+ctx.run_id+'-status-'+digest[:16]+'.json', raw)
    if api.file(saved['file_id']) != raw: raise ValueError('moi_status_readback_mismatch')
    objects.publish(receipt_key, json_bytes(saved), 'application/json')
    return dict(synced=True, file_id=saved['file_id'], sha256=digest, minio_key=ctx.prefix+'/orchestration/status.json')


def main():
    import os
    from batch_context import BatchContext
    from cloud_daily import DailyAPI
    from resilient_storage import Objects
    ctx = BatchContext.from_env()
    api = DailyAPI(os.environ['MOI_API_KEY'])
    print(json.dumps(upload_saved(api, Objects.from_workspace(api), ctx)))




class StatusMonitor:
    """Periodic snapshots for the running batch, using fresh managed clients."""
    def __init__(self, callback, interval=60):
        import threading
        self.callback, self.interval = callback, interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.failure = None

    def loop(self):
        while not self.stop.wait(self.interval):
            try:
                self.callback()
                self.failure = None
            except Exception as exc:
                # Explicitly retried on the next heartbeat and at final sync.
                self.failure = type(exc).__name__

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join()


if __name__ == '__main__': main()
