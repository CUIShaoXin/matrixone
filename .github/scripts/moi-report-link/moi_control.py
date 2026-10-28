"""Owner-facing control entry; no scheduler, scanner or sender is implemented here.

The MOI run owner must supply its persisted run ID and managed credentials.
This callable/CLI is not a deployed MOI API and does not grant tool access.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import uuid

from batch_context import BatchContext, LOCAL
from cloud_daily import DailyAPI, WORKSPACE, json_bytes
from daily_delivery import create_once, read_json
import moi_actions
import orchestration_status
from resilient_storage import Objects


class Controller:
    def __init__(self, actions, api, objects):
        self.actions, self.api, self.objects = actions, api, objects

    @staticmethod
    def owner_key(owner_run_id):
        if not isinstance(owner_run_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', owner_run_id):
            raise ValueError('moi_owner_run_id_required')
        digest = hashlib.sha256(owner_run_id.encode()).hexdigest()
        return 'receipts/moi/owner-runs/'+digest+'.json'

    def lookup(self, owner_run_id):
        alias = read_json(self.objects, self.owner_key(owner_run_id), missing=True)
        if alias is None:
            raise ValueError('moi_batch_not_found')
        if alias.get('owner_run_id') != owner_run_id or alias.get('workspace_id') != WORKSPACE:
            raise ValueError('moi_owner_binding_conflict')
        batch = read_json(self.objects, alias['batch_key'])
        if batch.get('workspace_id') != WORKSPACE or batch.get('run_id') != alias['run_id']:
            raise ValueError('moi_owner_binding_conflict')
        self.check_request(batch, **{k: alias['request'][k] for k in (
            'business_date', 'execution_mode', 'runtime_ref', 'workflow_ref')})
        return batch

    @staticmethod
    def context(batch):
        return BatchContext(batch['run_id'], batch['business_date'], batch['trigger_source'],
                            batch['execution_mode'], {})

    def prepare(self, *, owner_run_id, trigger_source, execution_mode, runtime_ref,
                workflow_ref, business_date=None, now=None):
        owner_key = self.owner_key(owner_run_id)
        current_date = (now or dt.datetime.now(LOCAL)).astimezone(LOCAL).date().isoformat()
        candidate = BatchContext.from_env(dict(MATRIX_PIPELINE_RUN_ID='validate-control-request',
            MATRIX_BUSINESS_DATE=current_date if business_date is None else business_date, MATRIX_TRIGGER_SOURCE=trigger_source,
            MATRIX_EXECUTION_MODE=execution_mode))
        moi_actions.validate_dispatch_inputs(candidate, runtime_ref, workflow_ref)
        date = candidate.business_date
        scope = 'production' if execution_mode == 'production' else hashlib.sha256(owner_run_id.encode()).hexdigest()
        key = 'receipts/'+date.replace('-', '')+'/moi-batches/'+scope+'.json'
        run_id = 'daily-'+date.replace('-', '') if execution_mode == 'production' else 'moi-test-'+date.replace('-', '')+'-'+uuid.uuid4().hex
        reserved_request = dict(workspace_id=WORKSPACE,
            business_date=date, trigger_source=trigger_source, execution_mode=execution_mode,
            runtime_ref=runtime_ref, workflow_ref=workflow_ref)
        # Reserve the owner's date and identity first. A lost acknowledgement
        # or restart across midnight must not select another day's batch.
        link = dict(workspace_id=WORKSPACE, owner_run_id=owner_run_id,
                    batch_key=key, run_id=run_id, request=reserved_request)
        _, saved_link = create_once(self.objects, owner_key, link)
        if saved_link.get('owner_run_id') != owner_run_id or saved_link.get('workspace_id') != WORKSPACE:
            raise ValueError('moi_owner_binding_conflict')
        self.check_request(saved_link['request'], business_date, execution_mode, runtime_ref, workflow_ref)
        initial = dict(saved_link['request'], schema='matrix_moi_batch_v1',
            run_id=saved_link['run_id'], created_by_owner_run_id=owner_run_id,
            created_at=dt.datetime.now(dt.timezone.utc).isoformat())
        create_once(self.objects, saved_link['batch_key'], initial)
        return self.lookup(owner_run_id)

    @staticmethod
    def check_request(batch, business_date, execution_mode, runtime_ref, workflow_ref):
        expected = dict(workspace_id=WORKSPACE, execution_mode=execution_mode,
                        runtime_ref=runtime_ref, workflow_ref=workflow_ref)
        if business_date is not None:
            expected['business_date'] = business_date
        if any(batch.get(k) != v for k, v in expected.items()):
            raise ValueError('moi_batch_request_conflict')

    def start(self, **request):
        batch = self.prepare(**request)
        ctx = self.context(batch)
        # An old schedule may already own this day's checkpoints. The new
        # entry must not silently start a second workflow for that batch.
        if (read_json(self.objects, ctx.prefix+'/checkpoint.json', missing=True) is not None
                and read_json(self.objects, ctx.prefix+'/orchestration/dispatch.json', missing=True) is None):
            raise ValueError('existing_batch_requires_reconciliation')
        result = moi_actions.dispatch(self.actions, self.objects, ctx,
                                      batch['runtime_ref'], batch['workflow_ref'])
        return dict(batch=batch, dispatch=result)

    def status(self, owner_run_id):
        batch = self.lookup(owner_run_id)
        ctx = self.context(batch)
        observed = moi_actions.observe_dispatch(self.actions, self.objects, ctx)
        snapshot = read_json(self.objects, ctx.prefix+'/orchestration/status.json', missing=True)
        if snapshot is not None:
            orchestration_status.check_identity(snapshot, ctx)
        result = dict(batch=batch, dispatch=observed, snapshot=snapshot)
        if observed.get('github_attempt', 1) > 1:
            key = self.retry_key(ctx, observed['github_run_id'], observed['github_attempt']-1)
            retry = read_json(self.objects, key, missing=True)
            if retry is not None:
                result['retry'] = moi_actions.update_dispatch(self.objects, key, retry['request_sha256'], dict(
                    state=observed['state'], github_run_id=observed['github_run_id'],
                    github_attempt=observed['github_attempt'], conclusion=observed['conclusion']))
        return result

    @staticmethod
    def retry_key(ctx, github_run_id, attempt):
        return ctx.prefix+'/orchestration/retries/'+str(github_run_id)+'-'+str(attempt)+'.json'

    def resume(self, owner_run_id, *, max_retries):
        if type(max_retries) is not int or max_retries < 1:
            raise ValueError('configured_retry_limit_required')
        result = self.status(owner_run_id)
        observed, snapshot = result['dispatch'], result['snapshot'] or {}
        if snapshot.get('sent') is True or snapshot.get('business_status') == 'succeeded':
            return dict(result, retry=dict(state='status_sync_required'))
        if observed['state'] in ('queued', 'pending', 'waiting', 'requested', 'in_progress'):
            return result
        if observed['state'] != 'completed':
            raise ValueError('github_run_binding_required')
        if observed['conclusion'] == 'success':
            return dict(result, retry=dict(state='already_completed'))
        if observed['conclusion'] not in ('failure', 'cancelled', 'timed_out', 'startup_failure'):
            raise ValueError('github_run_not_retryable')
        if observed['github_attempt']-1 >= max_retries:
            raise ValueError('github_retry_limit_reached')
        batch = result['batch']
        ctx = self.context(batch)
        key = self.retry_key(ctx, observed['github_run_id'], observed['github_attempt'])
        path = '/actions/runs/'+str(observed['github_run_id'])+'/rerun'
        request = dict(path=path, previous_attempt=observed['github_attempt'])
        digest = hashlib.sha256(json_bytes(request)).hexdigest()
        initial = dict(schema='matrix_moi_retry_v1', run_id=ctx.run_id, business_date=ctx.business_date,
            request=request, request_sha256=digest, state='submitting',
            created_at=dt.datetime.now(dt.timezone.utc).isoformat())
        created, retry = create_once(self.objects, key, initial)
        if retry['request_sha256'] != digest:
            raise ValueError('dispatch_batch_request_conflict')
        if created:
            retry = moi_actions.submit_intent(self.actions, self.objects, key, digest, path, {})
        refreshed = self.status(owner_run_id)
        return dict(refreshed, retry=refreshed.get('retry', retry))

    def sync(self, owner_run_id, *, reconcile=False):
        ctx = self.context(self.lookup(owner_run_id))
        if reconcile:
            return moi_actions.reconcile(self.actions, self.api, self.objects, ctx)
        return orchestration_status.upload_saved(self.api, self.objects, ctx)


class GitHubCLI:
    """Use the caller's managed gh login without exporting its token."""
    def request(self, path, payload=None):
        if not path.startswith('/actions/') or '://' in path or '..' in path or any(ord(c) < 32 for c in path):
            raise ValueError('invalid_github_actions_route')
        command = ['gh', 'api', '--hostname', 'github.com', '--method',
                   'GET' if payload is None else 'POST', '/repos/'+moi_actions.REPOSITORY+path]
        raw = None
        if payload is not None:
            command.extend(['--input', '-'])
            raw = json.dumps(payload).encode()
        response = subprocess.run(command, input=raw, capture_output=True, timeout=45)
        if response.returncode:
            match = re.search(rb'HTTP ([1-5][0-9]{2})', response.stderr)
            if match:
                raise urllib.error.HTTPError('https://api.github.com/repos/'+moi_actions.REPOSITORY+path,
                    int(match.group(1)), 'github_cli_request_failed', {}, None)
            raise RuntimeError('github_cli_request_failed')
        return json.loads(response.stdout) if response.stdout.strip() else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'start', 'status', 'resume', 'status-sync', 'status-reconcile'))
    parser.add_argument('--owner-run-id', required=True, help='Persisted run ID injected by the MOI owner')
    parser.add_argument('--business-date')
    parser.add_argument('--trigger-source', choices=('moi_manual', 'moi_api', 'moi_schedule'), default='moi_manual')
    parser.add_argument('--execution-mode', choices=('no_send', 'production'), default='no_send')
    parser.add_argument('--runtime-ref')
    parser.add_argument('--workflow-ref')
    parser.add_argument('--max-retries', type=int, help='Explicit retry limit from the approved owner configuration')
    args = parser.parse_args(argv)
    try:
        api = DailyAPI(os.environ.get('MOI_API_KEY'))
        actions = moi_actions.GitHubActions(os.environ['GITHUB_ACTIONS_TOKEN']) if os.environ.get('GITHUB_ACTIONS_TOKEN') else GitHubCLI()
        controller = Controller(actions, api, Objects.from_workspace(api))
        if args.operation in ('prepare', 'start'):
            if not args.runtime_ref or not args.workflow_ref:
                raise ValueError('reviewed_runtime_and_workflow_ref_required')
            request = dict(owner_run_id=args.owner_run_id, business_date=args.business_date,
                trigger_source=args.trigger_source, execution_mode=args.execution_mode,
                runtime_ref=args.runtime_ref, workflow_ref=args.workflow_ref)
            result = controller.prepare(**request) if args.operation == 'prepare' else controller.start(**request)
        elif args.operation == 'status':
            result = controller.status(args.owner_run_id)
        elif args.operation == 'resume':
            result = controller.resume(args.owner_run_id, max_retries=args.max_retries)
        else:
            result = controller.sync(args.owner_run_id, reconcile=args.operation == 'status-reconcile')
        print(json.dumps(dict(operation=args.operation, result=result), ensure_ascii=False))
        return 1 if any(result.get(k, {}).get('state') in ('unknown', 'rejected') for k in ('dispatch', 'retry')) else 0
    except Exception as exc:
        error = dict(operation=args.operation, status='blocked', error_type=type(exc).__name__)
        if re.fullmatch(r'[a-z][a-z0-9_]{0,100}', str(exc)):
            error['code'] = str(exc)
        print(json.dumps(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
