"""Bounded first processing of an original registered file, never a failed retry."""
import datetime as dt
import hashlib
import time

from pipeline_telemetry import emit

SCHEMA = 'matrix_kb_initial_trigger_v1'
WAIT_SECONDS = 120
OBSERVATION_SECONDS = 30


def same_source(found, fid):
    return (len(found) == 1 and found[0].get('ingest_status') == 'pending'
            and not found[0].get('error') and found[0].get('source_id')
            and found[0].get('source_file_id') == fid
            and found[0].get('kb_file_id') == fid)


def mounted(api, fid, volume_id, deadline):
    from knowledge_gate import fact_timeout
    total = None; seen = set(); present = False
    for page in range(1, 101):
        value = api.data(api.request('/catalog/file/list', dict(
            filters=[dict(name='volume_id', values=[str(volume_id)])],
            page=page, page_size=100), timeout=min(15, fact_timeout(deadline)), retry=False))
        entries = value.get('list'); count = value.get('total')
        if (not isinstance(entries, list) or type(count) is not int or count < 0
                or (total is not None and total != count)):
            raise ValueError('knowledge_initial_mount_inventory_changed')
        total = count
        ids = [v.get('file_id', v.get('id')) for v in entries]
        if any(not v for v in ids) or len(set(ids)) != len(ids) or seen.intersection(ids):
            raise ValueError('knowledge_initial_mount_inventory_changed')
        seen.update(ids); present = present or fid in ids
        if len(seen) == total:
            if not present: raise ValueError('knowledge_initial_original_not_mounted')
            return
        if len(seen) > total or len(entries) != 100:
            raise ValueError('knowledge_initial_mount_inventory_incomplete')
    raise ValueError('knowledge_initial_mount_inventory_incomplete')


def recover(job, artifact, target, found, state, volume_id):
    from knowledge_gate import KB_WORKFLOW_ID, WORKFLOWS, execution_facts, fact_timeout, rows, matching
    from daily_delivery import create_once
    fid = artifact['file_id']; deadline = state['ingestion_deadline_epoch']
    previous = state.get('initial_trigger')
    if previous:
        if (previous.get('schema') != SCHEMA or previous.get('file_id') != fid
                or previous.get('artifact_sha256') != artifact.get('sha256')
                or previous.get('workflow_id') != KB_WORKFLOW_ID
                or previous.get('attempts') != 1
                or previous.get('request') != dict(volume_id=volume_id, file_ids=[fid])):
            raise ValueError('knowledge_initial_checkpoint_identity_mismatch')
        # A durable reservation consumes permission even if the process stopped
        # before POST. Normal materialization/fact reads observe the original.
        if previous.get('status') == 'rejected':
            raise ValueError('knowledge_initial_trigger_rejected')
        return True
    if (volume_id != 140002 or not target or target.get('file_id') != fid
            or not target.get('marker') or not same_source(found, fid)
            or not isinstance(artifact.get('bytes'), int) or not artifact.get('sha256')):
        return False
    if time.time() >= deadline: raise ValueError('knowledge_ingestion_deadline')
    if state.get('lineage_recovery') or state.get('save_node_recovery'):
        return False
    first = state.get('ingestion_started_epoch')
    if first is None:
        if 'initial_trigger_first_seen_epoch' not in state:
            state['initial_trigger_first_seen_epoch'] = time.time()
            job.journal.save()
        first = state['initial_trigger_first_seen_epoch']
    if time.time() - first < WAIT_SECONDS:
        return False
    facts = execution_facts(job, fid, deadline)
    if facts: return False
    now = time.time()
    if 'initial_no_execution_first_observed_epoch' not in state:
        state['initial_no_execution_first_observed_epoch'] = now
        job.journal.save()
        return False
    if now - state['initial_no_execution_first_observed_epoch'] < OBSERVATION_SECONDS:
        return False
    route = WORKFLOWS + '/' + KB_WORKFLOW_ID
    definition = job.api.data(job.api.request(route, timeout=min(15, fact_timeout(deadline)), retry=False))['workflow']
    if (definition.get('id') != KB_WORKFLOW_ID or definition.get('status') != 'ready'
            or definition.get('execution_mode') != 'volume_trigger'
            or definition.get('trigger_summary') != dict(mode='volume_trigger', configured=True, enabled=True, volume_id=volume_id)
            or not definition.get('latest_workflow_version_id')):
        raise ValueError('knowledge_initial_workflow_identity_mismatch')
    if definition.get('execution_summary', {}).get('active_executions') != 0:
        return False
    mounted(job.api, fid, volume_id, deadline)
    raw = job.api.file(fid)
    if (len(raw) != artifact['bytes'] or hashlib.sha256(raw).hexdigest() != artifact['sha256']
            or target['marker'].encode() not in raw):
        raise ValueError('knowledge_initial_original_hash_mismatch')
    # Re-observe authoritative source and execution facts after the preflight.
    if not same_source(matching(rows(job.api, deadline), fid), fid):
        return False
    if execution_facts(job, fid, deadline): return False
    current = job.api.data(job.api.request(route, timeout=min(15, fact_timeout(deadline)), retry=False))['workflow']
    if (current.get('latest_workflow_version_id') != definition['latest_workflow_version_id']
            or current.get('status') != 'ready' or current.get('trigger_summary') != definition['trigger_summary']):
        raise ValueError('knowledge_initial_workflow_changed')
    if current.get('execution_summary', {}).get('active_executions') != 0: return False
    if time.time() >= deadline: raise ValueError('knowledge_ingestion_deadline')
    request = dict(volume_id=volume_id, file_ids=[fid])
    reservation = dict(schema=SCHEMA, file_id=fid, artifact_sha256=artifact['sha256'],
        workflow_id=KB_WORKFLOW_ID, workflow_version_id=current['latest_workflow_version_id'],
        source_id=found[0]['source_id'], attempts=1, request=request,
        original_ingestion_deadline_epoch=deadline, status='submission_unknown',
        reserved_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    # Cross-process, cross-journal permission is owned by a single conditional
    # create. Losing its acknowledgement cannot authorize POST on a restart.
    key = 'recoveries/kb-initial-trigger/' + fid + '.json'
    try:
        created, existing = create_once(job.objects, key, reservation)
    except Exception:
        raise ValueError('knowledge_initial_reservation_unconfirmed') from None
    for k in ('schema', 'file_id', 'artifact_sha256', 'workflow_id', 'request', 'attempts'):
        if existing.get(k) != reservation[k]:
            raise ValueError('knowledge_initial_reservation_identity_mismatch')
    state['initial_trigger'] = dict(existing)
    try:
        job.journal.save()
    except Exception:
        raise ValueError('knowledge_initial_checkpoint_unconfirmed') from None
    if not created: return True
    if time.time() >= deadline: raise ValueError('knowledge_ingestion_deadline')
    try:
        response = job.api.data(job.api.request('/catalog/file/trigger_workflow', request,
            method='POST', timeout=min(45, fact_timeout(deadline)), retry=False))
    except Exception as exc:
        state['initial_trigger']['submission_error_type'] = type(exc).__name__
        job.journal.save()
        emit('knowledge_initial_submission_unknown', same_sources=True, attempts=1)
        return True
    if not isinstance(response, dict) or type(response.get('triggered')) is not int or response['triggered'] != 1:
        state['initial_trigger'].update(status='rejected', response=response)
        job.journal.save()
        raise ValueError('knowledge_initial_trigger_rejected')
    state['initial_trigger'].update(status='acknowledged', response=response)
    job.journal.save()
    emit('knowledge_initial_trigger_acknowledged', same_sources=True, attempts=1)
    return True
