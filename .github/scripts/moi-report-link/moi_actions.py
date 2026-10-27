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
        runs = actions.request('/actions/workflows/'+WORKFLOW+'/runs?event=workflow_dispatch&per_page=100')
        title = 'MOI security managed - '+ctx.run_id
        matches = [run for run in runs['workflow_runs'] if run['display_title']==title
                   and run['created_at']>=saved['created_at'][:19]+'Z']
        if len(matches)>1: raise ValueError('github_run_correlation_ambiguous')
        if matches:
            run = matches[0]
            saved.update(state=run['status'], conclusion=run.get('conclusion'), github_run_id=run['id'],
                         github_attempt=run['run_attempt'], github_url=run['html_url'])
            objects.publish(key, json_bytes(saved), 'application/json')
    return saved
