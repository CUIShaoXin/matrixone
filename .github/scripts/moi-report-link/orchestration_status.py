"""Replayable MOI file snapshots; replay never starts a scan or sends a message."""
import datetime as dt
import hashlib
import json
from pathlib import Path

from cloud_daily import json_bytes
from daily_delivery import read_json

REPOSITORIES = (('matrixone', 'main'), ('taas', 'main'), ('matrixflow', 'dev'))


def check_identity(value, ctx):
    if (value.get('run_id'), value.get('business_date')) != (ctx.run_id, ctx.business_date):
        raise ValueError('status_identity_mismatch')
    if value.get('execution_mode', ctx.execution_mode) != ctx.execution_mode:
        raise ValueError('batch_execution_mode_conflict')


def registered_context(objects, ctx, value):
    """A registered retry can precede its first status heartbeat.

    Advance only a snapshot known to precede that retry in the execution
    journal. A newer snapshot absent from the journal must never be downgraded.
    """
    from dataclasses import replace
    from moi_actions import github_identity
    root = read_json(objects, ctx.prefix+'/checkpoint.json', missing=True) or {}
    executions = root.get('executions', [])
    if not executions: return None
    latest = executions[-1]
    if value is not None:
        github = value.get('github')
        if github == latest.get('github') or not any(e.get('github') == github for e in executions[:-1]):
            return None
    check_identity(latest, ctx)
    return replace(ctx, github=github_identity(latest.get('github', {})), trigger_source=latest['trigger_source'])


def apply_terminal(objects, ctx, value):
    """Project a verified Actions terminal result without inventing scan/send results."""
    from moi_actions import terminal_key
    github = value.get('github', {})
    if github.get('run_id') in (None, 'manual'): return value
    evidence = read_json(objects, terminal_key(ctx, github), missing=True)
    if evidence is None: return value
    if ((evidence.get('run_id'), evidence.get('business_date'), evidence.get('github'))
            != (ctx.run_id, ctx.business_date, github)
            or evidence.get('schema') != 'matrix_github_terminal_v1'
            or evidence.get('status') != 'completed'):
        raise ValueError('github_terminal_evidence_conflict')
    business = value.setdefault('business_status', value.get('status', 'waiting'))
    conclusion = evidence['conclusion']
    if conclusion == 'success':
        status = business if business in ('succeeded', 'failed') else 'incomplete'
        code = 'github_success_without_business_completion' if status == 'incomplete' else None
    else:
        states = dict(cancelled='cancelled', timed_out='timed_out', failure='failed', startup_failure='failed',
                      neutral='incomplete', skipped='incomplete', stale='incomplete', action_required='incomplete')
        if conclusion not in states: raise ValueError('github_run_conclusion_invalid')
        status, code = states[conclusion], 'github_actions_'+conclusion
    value['status'] = status
    stages = value.setdefault('stages', {})
    for repo in value.get('repositories', {}).values():
        if repo.get('status') == 'running': repo['status'] = 'unknown'
        for name, current in repo.get('stages', {}).items():
            if current == 'running': repo['stages'][name] = 'unknown'
    for item in stages.values():
        if isinstance(item, dict) and item.get('status') in ('running', 'waiting_for_delivery_time'):
            item.update(status='unknown', code='github_execution_ended_before_stage_confirmation')
    stages['github_actions'] = evidence
    if 'overall' in stages: stages['overall']['status'] = status
    if value.get('sent') is not True:
        value['sent'] = False if value.get('execution_mode') == 'no_send' else None
    if code:
        value.setdefault('failure_stage', 'github_actions')
        failure = dict(stage='github_actions', code=code)
        failures = value.setdefault('failures', [])
        if failure not in failures: failures.append(failure)
    return value


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
                            'code_repository', 'api_context_for', 'api_publish_report',
                            'knowledge_ingestion'): continue
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
            repositories = reviews.get(field, {})
            item = repositories.get(repo, {})
            target['stages'][label] = 'succeeded' if item.get('accepted') else ('running' if repo in repositories else 'waiting')
        repositories = components.get('repositories', {})
        item = repositories.get(repo, {})
        target['stages']['component_scan'] = 'succeeded' if item.get('accepted') else ('running' if repo in repositories else 'waiting')
        for failure in root.get('failures', []):
            if failure.get('repository') == repo and failure.get('stage') == 'components' and not item.get('accepted'):
                target['stages']['component_scan'] = 'failed'
        if not item.get('accepted') and item.get('scan_status') in ('running', 'failed'):
            target['stages']['component_scan'] = item['scan_status']
        target['component_failure'] = item.get('scan_failure')
        attempts = components.get('workflow_recovery', {}).get(repo+'_finalize', {}).get('attempts', [])
        target['component_attempts'] = [dict(attempt,
            workflow_status=components.get('stages', {}).get(attempt['label'], {}).get('status', 'planned'))
            for attempt in attempts]
        target['component_retry_count'] = max(0, len(attempts)-1)
        for failure in reviews.get('issues', []):
            for label, prefix in (('code_review', 'code_'), ('api_port_review', 'api_')):
                if failure.get('stage') == prefix+repo and target['stages'][label] != 'succeeded':
                    target['stages'][label] = 'failed'
    publication_stage = value['stages'].get('api_publish_report', {})
    report_status = ('succeeded' if root.get('published') else
                     'failed' if publication_stage.get('status') == 'failed' else
                     'running' if publication_stage else 'waiting')
    value['stages']['report'] = dict(status=report_status)
    overall = value['stages'].get('overall', {})
    value['status'] = overall.get('status', 'running')
    delivery = value['stages'].get('delivery', {})
    value['sent'] = delivery.get('sent', overall.get('sent', False))
    value['delivery_receipt_file_id'] = delivery.get('receipt_file_id', overall.get('receipt_file_id'))
    value['failures'] = root.get('failures', []) + reviews.get('issues', [])
    phase = overall.get('failure_stage')
    if phase:
        # The scanner returns a nonzero status after writing its safe reason;
        # the entry's overall record can consequently contain only the phase.
        # Keep that producer's reason when projecting the same failed run.
        scan = value['stages'].get('scan', {})
        failure = dict(scan if phase == 'scan' and scan.get('status') == 'failed' else {})
        failure.update(overall)
        fields = {k: failure[k] for k in ('safe_code', 'error_type', 'reason_type', 'http_status') if k in failure}
        value.update(failure_stage=phase, **fields)
        evidence = dict(stage=phase, **fields)
        if evidence not in value['failures']: value['failures'].append(evidence)
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
    return apply_terminal(objects, ctx, value)


def sync(api, objects, ctx):
    value = snapshot(api, objects, ctx)
    key = ctx.prefix+'/orchestration/status.json'
    raw = json_bytes(value)
    # The complete status survives a MOI outage before upload is attempted.
    objects.publish(key, raw, 'application/json')
    return upload_saved(api, objects, ctx)


def upload_saved(api, objects, ctx):
    key = ctx.prefix+'/orchestration/status.json'
    for attempt in range(3):
        _, headers, original = objects.call('GET', key)
        value = json.loads(original)
        check_identity(value, ctx)
        registered = registered_context(objects, ctx, value)
        if registered is not None:
            previous = value
            value = snapshot(api, objects, registered)
            value['previous_execution'] = dict(github=previous['github'], status=previous['status'],
                                                business_status=previous.get('business_status', previous['status']))
            if previous.get('sent') is True and previous.get('delivery_receipt_file_id'):
                value.update(sent=True, delivery_receipt_file_id=previous['delivery_receipt_file_id'])
        value = apply_terminal(objects, ctx, value)
        report_error = None
        if value.get('report_details', {}).get('status') == 'pending':
            try:
                publication = json.loads(api.file(value['publication_file_id']))
                value['report_url'] = publication['url']
                value['report_expires_at_utc'] = publication['expires_at_utc']
                value['report_details'] = dict(status='succeeded')
            except Exception as exc:
                # Persist terminal evidence even when report enrichment needs
                # MOI recovery. The caller still receives the actual failure.
                report_error = exc
        if value == json.loads(original):
            raw = original
            break
        raw = json_bytes(value)
        etag = next((v for k,v in headers.items() if k.lower() == 'etag'), None)
        if not etag: raise ValueError('status_etag_required')
        try:
            objects.call('PUT', key, raw=raw, headers={'if-match':etag, 'content-type':'application/json',
                         'x-amz-meta-sha256':hashlib.sha256(raw).hexdigest()})
        except RuntimeError as exc:
            if str(exc) != 'minio_http_412': raise
            continue
        # A successful write may immediately be superseded by a new attempt.
        if objects.call('GET', key)[2] == raw: break
    else:
        raise ValueError('status_update_contended')
    if report_error is not None: raise report_error
    digest = hashlib.sha256(raw).hexdigest()
    receipt_key = ctx.prefix+'/orchestration/sync-'+digest+'.json'
    saved = read_json(objects, receipt_key, missing=True)
    if saved is None:
        saved = api.upload('matrix-run-'+ctx.run_id+'-status-'+digest[:16]+'.json', raw)
    if api.file(saved['file_id']) != raw: raise ValueError('moi_status_readback_mismatch')
    objects.publish(receipt_key, json_bytes(saved), 'application/json')
    return dict(synced=True, file_id=saved['file_id'], sha256=digest, minio_key=key,
                github=value.get('github'), github_conclusion=value.get('stages', {}).get('github_actions', {}).get('conclusion'))


def main():
    import argparse
    import os
    from batch_context import BatchContext
    from cloud_daily import DailyAPI
    from resilient_storage import Objects
    parser = argparse.ArgumentParser()
    parser.add_argument('--reconcile-actions', action='store_true')
    args = parser.parse_args()
    ctx = BatchContext.from_env()
    api = DailyAPI(os.environ['MOI_API_KEY'])
    objects = Objects.from_workspace(api)
    if args.reconcile_actions:
        from moi_actions import GitHubActions, reconcile
        result = reconcile(GitHubActions(os.environ['GITHUB_ACTIONS_TOKEN']), api, objects, ctx)
    else:
        result = upload_saved(api, objects, ctx)
    print(json.dumps(result))




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
