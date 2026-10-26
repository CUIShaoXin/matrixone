"""Retire owned one-shot apps after durable evidence and resumable outputs exist.

Catalog files, KB sources and published reports are never deleted. A changed or
active app is retained and recorded for inspection, rather than guessed safe.
"""
import datetime as dt
import hashlib
import json
import re
import uuid


TERMINAL = {'completed', 'failed', 'cancelled', 'canceled', 'error', 'timeout'}


def packed(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def cached_outputs(runner, stage, nodes):
    evidence = stage.get('output_artifacts')
    if evidence is None:
        return None
    expected = {n['name']: n['input']['output_file_name'] for n in nodes
                if n['id'] == 'moi:catalog.sink.write'}
    if set(evidence) != set(expected):
        raise ValueError('workflow_output_cache_coverage_mismatch')
    result = {}
    for name, item in evidence.items():
        if item['name'] != expected[name] or not item.get('readback_verified'):
            raise ValueError('workflow_output_cache_identity_mismatch')
        raw = runner.api.file(item['file_id'])
        if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
            raise ValueError('workflow_output_cache_hash_mismatch')
        result[name] = (item, raw)
    return result


def retire(runner, label):
    """Best-effort cleanup with durable failure status; never retry execution."""
    stage = runner.state['stages'][label]
    if stage.get('cleanup', {}).get('status') == 'deleted':
        return
    try:
        _retire(runner, label, stage)
    except Exception as exc:
        error = str(exc)
        if not re.fullmatch('[a-z][a-z0-9_]{0,100}', error):
            error = type(exc).__name__
        stage['cleanup'] = dict(status='pending', safe_error=error,
                                at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        runner.journal.save()
        runner.event(stage=label, status='workflow_cleanup_pending', safe_error=error)


def _retire(runner, label, stage):
    from cloud_daily import WORKSPACE
    wid, eid = stage['workflow_id'], stage['execution_id']
    expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                WORKSPACE+'/matrix-daily-reusable-v2/'+label))
    if wid != expected_id or stage['status'] not in TERMINAL:
        raise ValueError('workflow_cleanup_ownership_or_state_mismatch')
    if stage['status'] == 'completed' and 'output_artifacts' not in stage:
        raise ValueError('workflow_cleanup_outputs_not_cached')
    route = '/workflow/v2/workflow-apps/'+wid
    try:
        definition = runner.api.data(runner.api.request(route))['workflow']
    except Exception as exc:
        if str(exc) != 'moi_http_404' or not stage.get('workflow_archive'):
            raise
        # Lost DELETE response or a process crash after confirmed archive.
        _check_archive(runner, stage['workflow_archive'])
        stage['cleanup'] = dict(status='deleted', confirmed_http=404)
        runner.journal.save()
        return
    summary = definition.get('execution_summary', {})
    if (definition.get('id') != wid or definition.get('name') != 'Matrix daily '+label
            or definition.get('execution_mode') != 'one_shot'
            or definition.get('description') != 'Dynamic fixed-commit manifest scan; no group send'
            or summary.get('active_executions') != 0
            or summary.get('latest_execution_id') != eid
            or summary.get('total_executions') != 1):
        raise ValueError('workflow_cleanup_app_changed_or_active')
    execution = runner.api.data(runner.api.request(
        '/workflow/v2/workflow-apps/executions/'+eid+'/result'))['result']
    if (execution.get('execution_id') != eid or execution.get('workflow_id') != wid
            or execution.get('status') not in TERMINAL):
        raise ValueError('workflow_cleanup_execution_not_terminal')
    output_backups = {}
    prefix = runner.state['prefix']+'/workflow-archives/'+wid+'/'+eid
    for name, item in stage.get('output_artifacts', {}).items():
        raw = runner.api.file(item['file_id'])
        if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
            raise ValueError('workflow_cleanup_output_hash_mismatch')
        output_backups[name] = runner.objects.publish(
            prefix+'/'+name+'.bin', raw, 'application/octet-stream')
    archive = dict(schema='matrix_owned_workflow_archive_v1', date=runner.state['date'],
                   run_id=runner.state['run_id'], label=label, workflow=definition,
                   result=execution, outputs=stage.get('output_artifacts', {}),
                   output_backups=output_backups)
    stage['workflow_archive'] = runner.objects.publish(
        prefix+'/archive.json', packed(archive), 'application/json')
    runner.journal.save()
    _check_archive(runner, stage['workflow_archive'])
    # Check again after backup; a new run or redeploy must block removal.
    current = runner.api.data(runner.api.request(route))['workflow']
    if current != definition:
        raise ValueError('workflow_cleanup_app_changed_during_backup')
    try:
        runner.api.request(route, method='DELETE', timeout=45)
    except Exception:
        # The independent GET reconciles an uncertain DELETE; no blind retry.
        pass
    try:
        runner.api.request(route)
    except Exception as exc:
        if str(exc) != 'moi_http_404':
            raise
    else:
        raise ValueError('workflow_cleanup_delete_unconfirmed')
    stage['cleanup'] = dict(status='deleted', confirmed_http=404,
                            at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    runner.journal.save()
    runner.event(stage=label, status='workflow_archived_and_retired')


def _check_archive(runner, item):
    raw = runner.objects.call('GET', item['key'], response_limit=item['bytes'])[2]
    if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
        raise ValueError('workflow_cleanup_archive_hash_mismatch')


def probe(api, objects, date, run_id):
    """An actual MOI save -> archive -> delete -> cached resume, without a scan."""
    from cloud_daily import Journal, Runner
    prefix = 'receipts/'+date.replace('-', '')+'/workflow-lifecycle-check-'+run_id
    journal = Journal(objects, prefix+'/checkpoint.json', dict(
        date=date, scope='workflow-lifecycle-check', run_id=run_id, prefix=prefix))
    runner = Runner(api, objects, journal)
    nodes = [runner.sink('probe', 'Matrix workflow lifecycle check '+run_id,
                         'matrix-workflow-lifecycle-'+run_id+'.txt', fmt='text')]
    first = runner.workflow('workflow_lifecycle_probe', nodes)
    stage = journal.value['stages']['workflow_lifecycle_probe']
    if stage.get('cleanup', {}).get('status') != 'deleted':
        raise ValueError('workflow_lifecycle_probe_cleanup_incomplete')
    second = runner.workflow('workflow_lifecycle_probe', nodes)
    if first != second:
        raise ValueError('workflow_lifecycle_probe_resume_changed_output')
    _check_archive(runner, stage['workflow_archive'])
    try:
        api.request('/workflow/v2/workflow-apps/'+stage['workflow_id'])
    except Exception as exc:
        if str(exc) != 'moi_http_404':
            raise
    else:
        raise ValueError('workflow_lifecycle_probe_app_still_present')
    return dict(workflow_lifecycle_verified=True, archived=True, deleted=True,
                cached_resume_verified=True, no_group_send=True,
                workflow_id=stage['workflow_id'], execution_id=stage['execution_id'])
