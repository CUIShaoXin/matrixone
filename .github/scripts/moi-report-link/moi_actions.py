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


def dispatch(actions, objects, ctx, runtime_ref):
    if not re.fullmatch(r'[0-9a-f]{40}', runtime_ref): raise ValueError('immutable_runtime_ref_required')
    if not ctx.trigger_source.startswith('moi_'): raise ValueError('moi_trigger_source_required')
    inputs = dict(mode='managed', runtime_ref=runtime_ref, run_id=ctx.run_id,
                  business_date=ctx.business_date, trigger_source=ctx.trigger_source,
                  execution_mode=ctx.execution_mode)
    request = dict(ref='main', inputs=inputs)
    key = ctx.prefix+'/orchestration/dispatch.json'
    digest = hashlib.sha256(json_bytes(request)).hexdigest()
    initial = dict(schema='matrix_moi_dispatch_v1', request=request, request_sha256=digest,
                   run_id=ctx.run_id, business_date=ctx.business_date, state='submitting',
                   created_at=dt.datetime.now(dt.timezone.utc).isoformat())
    created, saved = create_once(objects, key, initial)
    if saved['request_sha256'] != digest: raise ValueError('dispatch_batch_request_conflict')
    if created:
        try:
            actions.request('/actions/workflows/'+WORKFLOW+'/dispatches', request)
            saved['state'] = 'submitted'
        except urllib.error.HTTPError as exc:
            # A server failure may occur after acceptance; do not auto-resubmit.
            saved.update(state='rejected' if 400<=exc.code<500 and exc.code!=408 else 'unknown', http_status=exc.code)
        except Exception as exc:
            saved.update(state='unknown', error_type=type(exc).__name__)
        objects.publish(key, json_bytes(saved), 'application/json')
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
            saved.update(state=run['status'], conclusion=run.get('conclusion'), github_run_id=run['id'],
                         github_attempt=run['run_attempt'], github_url=run['html_url'])
            objects.publish(key, json_bytes(saved), 'application/json')
    return saved


def reconcile(actions, api, objects, ctx):
    """Observe one bound attempt; persist evidence before replaying MOI status.

    The status owner applies only evidence matching the snapshot it actually
    reads. An older observer cannot select a new run or resubmit business work.
    """
    from dataclasses import replace
    from orchestration_status import check_identity, snapshot, upload_saved
    key = ctx.prefix+'/orchestration/status.json'
    saved = read_json(objects, key, missing=True)
    if saved is not None:
        check_identity(saved, ctx)
        github = github_identity(saved.get('github', {}))
    else:
        intent = read_json(objects, ctx.prefix+'/orchestration/dispatch.json', missing=True)
        if intent is None: raise ValueError('github_run_binding_required')
        check_identity(dict(intent, execution_mode=intent['request']['inputs']['execution_mode']), ctx)
        github = github_identity(dict(run_id=intent.get('github_run_id'), attempt=intent.get('github_attempt')))
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
        inputs = intent['request']['inputs']
        bound = replace(ctx, github=github, trigger_source=inputs['trigger_source'])
        create_once(objects, key, snapshot(api, objects, bound))
    result = upload_saved(api, objects, ctx)
    result['terminal_applied'] = (result.get('github') == github
                                  and result.get('github_conclusion') == evidence['conclusion'])
    return result
