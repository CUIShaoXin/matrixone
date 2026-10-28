"""GitHub dispatch adapter with durable uncertain-result handling.

The caller supplies its managed GitHub token and object-store adapter. This
module does not read other owners' credentials or create a local scheduler.
"""
import datetime as dt
import hashlib
import json
import re
import urllib.error
import urllib.request

from cloud_daily import json_bytes
from daily_delivery import create_once, read_json

REPOSITORY = 'CUIShaoXin/matrixone'
WORKFLOW = 'moi-managed-security.yml'
BASE = 'https://api.github.com/repos/' + REPOSITORY


def github_identity(github):
    run_id, attempt = github.get('run_id'), github.get('attempt')
    if not re.fullmatch(r'[1-9][0-9]*', str(run_id)) or type(attempt) is not int or attempt < 1:
        raise ValueError('github_run_binding_required')
    return dict(run_id=str(run_id), attempt=attempt)


def terminal_key(ctx, github):
    identity = github_identity(github)
    return ctx.prefix+'/orchestration/actions/'+identity['run_id']+'/'+str(identity['attempt'])+'.json'


def verify_run(run, ctx, github=None):
    identity = github_identity(dict(run_id=run.get('id'), attempt=run.get('run_attempt')))
    if (run.get('display_title') != 'MOI security managed - '+ctx.run_id
            or run.get('event') != 'workflow_dispatch'
            or run.get('path', '').split('@')[0] != '.github/workflows/'+WORKFLOW
            or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('html_url') != 'https://github.com/'+REPOSITORY+'/actions/runs/'+identity['run_id']
            or (github is not None and identity != github_identity(github))):
        raise ValueError('github_run_identity_mismatch')
    return identity


class GitHubActions:
    def __init__(self, token):
        if not token: raise ValueError('github_actions_credential_required')
        self.token = token
        # Do not send Authorization to a redirect target.
        from cloud_preflight import NoRedirect
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, payload=None):
        request = urllib.request.Request(BASE+path, data=None if payload is None else json_bytes(payload),
            headers={'Authorization':'Bearer '+self.token, 'Accept':'application/vnd.github+json',
                     'Content-Type':'application/json', 'X-GitHub-Api-Version':'2022-11-28',
                     'User-Agent':'MOI-security-orchestrator'})
        with self.opener.open(request, timeout=40) as response:
            raw = response.read(8*1024*1024+1)
            if len(raw)>8*1024*1024: raise ValueError('github_response_too_large')
            return json.loads(raw) if raw else None


def update_dispatch(objects, key, request_sha256, observation):
    """Merge an observation without losing a concurrently persisted binding."""
    for attempt in range(3):
        _, headers, original = objects.call('GET', key)
        saved = json.loads(original)
        if saved['request_sha256'] != request_sha256:
            raise ValueError('dispatch_batch_request_conflict')
        if saved.get('github_run_id'):
            # A late POST acknowledgement cannot erase a run found by a poller.
            if not observation.get('github_run_id'):
                return saved
            if str(saved['github_run_id']) != str(observation['github_run_id']):
                raise ValueError('github_run_correlation_conflict')
            if observation['github_attempt'] < saved['github_attempt']:
                return saved
            if observation['github_attempt'] == saved['github_attempt'] and saved['state'] == 'completed':
                if observation['state'] != 'completed':
                    return saved
                if observation['conclusion'] != saved['conclusion']:
                    raise ValueError('github_run_terminal_conflict')
        elif saved['state'] == 'rejected' and observation.get('github_run_id'):
            raise ValueError('github_run_correlation_conflict')
        value = dict(saved, **observation)
        if value == saved:
            return saved
        etag = next((v for k, v in headers.items() if k.lower() == 'etag'), None)
        if not etag:
            raise ValueError('dispatch_etag_required')
        raw = json_bytes(value)
        try:
            objects.call('PUT', key, raw=raw, headers={'if-match': etag, 'content-type': 'application/json',
                         'x-amz-meta-sha256': hashlib.sha256(raw).hexdigest()})
        except RuntimeError as exc:
            if str(exc) != 'minio_http_412':
                raise
            continue
        if objects.call('GET', key)[2] == raw:
            return value
    raise ValueError('dispatch_update_contended')


def validate_dispatch_inputs(ctx, runtime_ref, workflow_ref):
    if not re.fullmatch(r'[0-9a-f]{40}', runtime_ref): raise ValueError('immutable_runtime_ref_required')
    if (not isinstance(workflow_ref, str) or not workflow_ref or workflow_ref != workflow_ref.strip()
            or any(ord(c) < 32 for c in workflow_ref)):
        raise ValueError('workflow_ref_required')
    if not ctx.trigger_source.startswith('moi_'): raise ValueError('moi_trigger_source_required')


def submit_intent(actions, objects, key, digest, path, request):
    try:
        actions.request(path, request)
        outcome = dict(state='submitted')
    except urllib.error.HTTPError as exc:
        # A server failure may occur after acceptance; do not auto-resubmit.
        outcome = dict(state='rejected' if 400<=exc.code<500 and exc.code!=408 else 'unknown', http_status=exc.code)
    except Exception as exc:
        outcome = dict(state='unknown', error_type=type(exc).__name__)
    return update_dispatch(objects, key, digest, outcome)


def dispatch(actions, objects, ctx, runtime_ref, workflow_ref):
    validate_dispatch_inputs(ctx, runtime_ref, workflow_ref)
    inputs = dict(mode='managed', runtime_ref=runtime_ref, run_id=ctx.run_id,
                  business_date=ctx.business_date, trigger_source=ctx.trigger_source,
                  execution_mode=ctx.execution_mode)
    request = dict(ref=workflow_ref, inputs=inputs)
    key = ctx.prefix+'/orchestration/dispatch.json'
    digest = hashlib.sha256(json_bytes(request)).hexdigest()
    initial = dict(schema='matrix_moi_dispatch_v1', request=request, request_sha256=digest,
                   run_id=ctx.run_id, business_date=ctx.business_date, state='submitting',
                   created_at=dt.datetime.now(dt.timezone.utc).isoformat())
    created, saved = create_once(objects, key, initial)
    if saved['request_sha256'] != digest: raise ValueError('dispatch_batch_request_conflict')
    if created:
        submit_intent(actions, objects, key, digest, '/actions/workflows/'+WORKFLOW+'/dispatches', request)
    return observe_dispatch(actions, objects, ctx)


def observe_dispatch(actions, objects, ctx):
    """Read an existing intent and its real run; never submit a workflow."""
    key = ctx.prefix+'/orchestration/dispatch.json'
    saved = read_json(objects, key, missing=True)
    if saved is None:
        return dict(state='not_submitted', run_id=ctx.run_id, business_date=ctx.business_date)
    request = saved['request']
    digest = hashlib.sha256(json_bytes(request)).hexdigest()
    expected = dict(run_id=ctx.run_id, business_date=ctx.business_date,
                    trigger_source=ctx.trigger_source, execution_mode=ctx.execution_mode)
    if (saved['request_sha256'] != digest
            or any(request['inputs'].get(k) != v for k, v in expected.items())):
        raise ValueError('dispatch_batch_request_conflict')
    # Matching is read-only even if POST timed out or process died afterwards.
    if saved['state'] != 'rejected':
        if saved.get('github_run_id'):
            identity = github_identity(dict(run_id=saved['github_run_id'], attempt=saved['github_attempt']))
            run = actions.request('/actions/runs/'+identity['run_id'])
            verified = verify_run(run, ctx)
            if verified['run_id'] != identity['run_id'] or verified['attempt'] < identity['attempt']:
                raise ValueError('github_run_identity_mismatch')
            matches = [run]
        else:
            runs = actions.request('/actions/workflows/'+WORKFLOW+'/runs?event=workflow_dispatch&per_page=100')
            title = 'MOI security managed - '+ctx.run_id
            matches = [run for run in runs['workflow_runs'] if run['display_title']==title
                       and run['created_at']>=saved['created_at'][:19]+'Z']
            if len(matches)>1: raise ValueError('github_run_correlation_ambiguous')
        if matches:
            run = matches[0]
            verify_run(run, ctx)
            saved = update_dispatch(objects, key, digest,
                dict(state=run['status'], conclusion=run.get('conclusion'), github_run_id=run['id'],
                     github_attempt=run['run_attempt'], github_url=run['html_url']))
    return saved


def reconcile(actions, api, objects, ctx):
    """Observe one bound attempt; persist evidence before replaying MOI status.

    The status owner applies only evidence matching the snapshot it actually
    reads. An older observer cannot select a new run or resubmit business work.
    """
    from dataclasses import replace
    from orchestration_status import check_identity, registered_context, snapshot, upload_saved
    key = ctx.prefix+'/orchestration/status.json'
    saved = read_json(objects, key, missing=True)
    if saved is not None: check_identity(saved, ctx)
    bound = registered_context(objects, ctx, saved)
    if bound is not None:
        github = bound.github
    elif saved is not None:
        github = github_identity(saved.get('github', {}))
    else:
        intent = read_json(objects, ctx.prefix+'/orchestration/dispatch.json', missing=True)
        if intent is None: raise ValueError('github_run_binding_required')
        check_identity(dict(intent, execution_mode=intent['request']['inputs']['execution_mode']), ctx)
        github = github_identity(dict(run_id=intent.get('github_run_id'), attempt=intent.get('github_attempt')))
        bound = replace(ctx, github=github, trigger_source=intent['request']['inputs']['trigger_source'])
    run = actions.request('/actions/runs/'+github['run_id']+'/attempts/'+str(github['attempt']))
    verify_run(run, ctx, github)
    if run.get('status') != 'completed':
        if run.get('conclusion') is not None: raise ValueError('github_run_status_invalid')
        return dict(synced=False, terminal_applied=False, github=github, github_status=run.get('status'))
    if run.get('conclusion') not in ('success', 'failure', 'cancelled', 'timed_out', 'neutral',
                                     'skipped', 'stale', 'action_required', 'startup_failure'):
        raise ValueError('github_run_conclusion_invalid')
    evidence = dict(schema='matrix_github_terminal_v1', run_id=ctx.run_id, business_date=ctx.business_date,
                    github=github, status=run['status'], conclusion=run['conclusion'],
                    url=run['html_url'], updated_at=run.get('updated_at'),
                    observed_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    _, prior = create_once(objects, terminal_key(ctx, github), evidence)
    for field in ('schema', 'run_id', 'business_date', 'github', 'status', 'conclusion', 'url'):
        if prior.get(field) != evidence[field]: raise ValueError('github_terminal_evidence_conflict')
    if saved is None:
        # Covers cancellation before checkout/first heartbeat. The identity is
        # the original dispatch's verified run, never this observer's run.
        create_once(objects, key, snapshot(api, objects, bound))
    result = upload_saved(api, objects, ctx)
    result['terminal_applied'] = (result.get('github') == github
                                  and result.get('github_conclusion') == evidence['conclusion'])
    return result
