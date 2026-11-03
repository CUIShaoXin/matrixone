"""Retained stage evidence. Private report URLs and free text stay in MOI."""
import hashlib
import json
from pathlib import Path
import re


STATES = frozenset(('waiting', 'running', 'unknown', 'succeeded', 'failed', 'passed',
    'accepted', 'completed', 'cancelled', 'timed_out', 'incomplete', 'pending',
    'queued', 'planned', 'skipped', 'preview_passed', 'waiting_for_delivery_time'))
REPOSITORIES = ('matrixone', 'taas', 'matrixflow')
IDENTIFIER = r'[A-Za-z0-9_-]{1,120}'
CONCLUSIONS = frozenset(('success', 'failure', 'cancelled', 'timed_out',
    'neutral', 'skipped', 'stale', 'action_required', 'startup_failure'))


def fields(value, specification):
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key, pattern in specification.items()
            if isinstance(value.get(key), str) and re.fullmatch(pattern, value[key])}


def failure(value):
    result = fields(value, dict(stage=IDENTIFIER, repository='matrixone|taas|matrixflow',
        code=r'[a-z][a-z0-9_]{0,100}', safe_code=r'[a-z][a-z0-9_]{0,100}',
        error_type=IDENTIFIER, reason_type=IDENTIFIER, error_code=r'[A-Za-z][A-Za-z0-9_]{0,100}',
        workflow_id=IDENTIFIER, execution_id=IDENTIFIER, workflow_label=IDENTIFIER))
    if not isinstance(value, dict):
        return result
    if value.get('status') in STATES:
        result['status'] = value['status']
    if value.get('conclusion') in CONCLUSIONS:
        result['conclusion'] = value['conclusion']
    if type(value.get('http_status')) is int and 100 <= value['http_status'] <= 599:
        result['http_status'] = value['http_status']
    for name in ('diagnostics', 'workflow_diagnostics', 'workflow'):
        if isinstance(value.get(name), dict):
            result[name] = failure(value[name])
    return result


def component_attempt(value):
    result = fields(value, dict(label=IDENTIFIER, workflow_id=IDENTIFIER,
        execution_id=IDENTIFIER, validation='pending|accepted|rejected'))
    if type(value.get('number')) is int and value['number'] > 0:
        result['number'] = value['number']
    if value.get('workflow_status') in STATES:
        result['workflow_status'] = value['workflow_status']
    if isinstance(value.get('failure'), dict):
        result['failure'] = failure(value['failure'])
    return result


def project(value, raw):
    result = fields(value, dict(run_id=r'[A-Za-z0-9_-]{1,80}',
        business_date=r'\d{4}-\d{2}-\d{2}',
        trigger_source='github_manual|github_schedule|moi_manual|moi_api|moi_schedule',
        execution_mode='no_send|production', failure_stage=IDENTIFIER,
        publication_file_id=IDENTIFIER, delivery_receipt_file_id=IDENTIFIER))
    result.update(schema='matrix_orchestration_evidence_v1',
        source_snapshot_sha256=hashlib.sha256(raw).hexdigest(),
        sent=value.get('sent') if type(value.get('sent')) is bool else None,
        repositories={}, stages={}, failures=[])
    result.update({key: item for key, item in failure(value).items()
                   if key in ('safe_code', 'error_type', 'reason_type', 'http_status')})
    if value.get('status') in STATES:
        result['status'] = value['status']
    if type(value.get('retry_count')) is int and value['retry_count'] >= 0:
        result['retry_count'] = value['retry_count']
    github = value.get('github', {})
    result['github'] = fields(github, dict(run_id=r'[0-9]+'))
    if type(github.get('attempt')) is int and github['attempt'] > 0:
        result['github']['attempt'] = github['attempt']
    for name in REPOSITORIES:
        repository = value.get('repositories', {}).get(name)
        if not isinstance(repository, dict):
            continue
        target = fields(repository, dict(branch='main|dev', commit=r'[a-f0-9]{40}',
            zip_sha256=r'[a-f0-9]{64}',
            minio_key=r'(?:receipts|snapshots)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*'))
        if any(part in ('.', '..') for part in target.get('minio_key', '').split('/')):
            target.pop('minio_key', None)
        for key in ('zip_bytes', 'attempts', 'component_retry_count'):
            if type(repository.get(key)) is int and repository[key] >= 0:
                target[key] = repository[key]
        target['stages'] = {key: state for key, state in repository.get('stages', {}).items()
            if key in ('version', 'download', 'validation', 'storage', 'component_scan',
                       'code_review', 'api_port_review') and isinstance(state, str) and state in STATES}
        for key in ('failure', 'component_failure'):
            if isinstance(repository.get(key), dict):
                target[key] = failure(repository[key])
        if isinstance(repository.get('component_attempts'), list):
            target['component_attempts'] = [component_attempt(item)
                for item in repository['component_attempts'] if isinstance(item, dict)]
        result['repositories'][name] = target
    for name, stage in value.get('stages', {}).items():
        if not re.fullmatch(r'[a-z_]+(?::(?:matrixone|taas|matrixflow))?', name):
            continue
        if isinstance(stage, dict):
            result['stages'][name] = failure(stage)
    result['failures'] = [failure(item) for item in value.get('failures', [])
                          if isinstance(item, dict)]
    return result


def write(value, raw, destination=Path('out/orchestration/evidence.json')):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix('.tmp')
    temporary.write_text(json.dumps(project(value, raw), ensure_ascii=False, indent=2)+'\n')
    temporary.replace(destination)
