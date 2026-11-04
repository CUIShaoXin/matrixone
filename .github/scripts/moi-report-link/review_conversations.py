"""New source reviews use explicit parentless conversations, never session forks.

Existing tasks remain immutable. Creation and inference have durable reservations;
an uncertain result is only read back. This is not an auth-failure retry path.
"""
import copy
import hashlib
import json
import urllib.error
import uuid

from cloud_daily import AGENT, WORKSPACE
from kimi_recovery import run_review


def require(value, code):
    if not value:
        raise ValueError(code)


class ReviewAPI:
    def __init__(self, job, repo, phase):
        self.job, self.original = job, job.api
        self.repo, self.phase = repo, phase

    def __getattr__(self, name):
        return getattr(self.original, name)

    def conversation(self, attempt):
        from daily_delivery import create_once
        cid = str(uuid.uuid5(uuid.NAMESPACE_URL,
                            WORKSPACE + '/matrix-source-review/' + attempt['request_id']))
        plan = dict(schema='matrix_review_conversation_v1', date=self.job.state['date'],
                    prefix=self.job.state['prefix'], repository=self.repo, phase=self.phase,
                    request_id=attempt['request_id'], conversation_id=cid,
                    workspace_id=WORKSPACE, agent_workspace_id=WORKSPACE, agent_id=AGENT,
                    parent_conversation_id='')
        route = '/workspaces/' + WORKSPACE + '/conversations'
        if 'root_conversation' not in attempt:
            # Saving before the first possible write makes a restart read-only,
            # including a crash before/after either remote reservation or POST.
            attempt['root_conversation'] = dict(plan=plan, creation_reserved=True)
            self.job.journal.save()
            created, prior = create_once(self.job.objects,
                                         'recoveries/review-conversations/' + cid + '.json', plan)
            require(prior == plan, 'review_conversation_reservation_conflict')
            if created:
                try:
                    self.original.request(route, dict(id=cid, agent_workspace_id=WORKSPACE,
                        agent_id=AGENT, title=self.job.state['date'] + ' ' + self.repo + ' ' + self.phase),
                        method='POST', retry=False)
                except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
                    if isinstance(exc, urllib.error.HTTPError) and exc.code not in (408,429,500,502,503,504):
                        raise
                    attempt['root_conversation']['create_acknowledgement'] = type(exc).__name__
                    self.job.journal.save()
                    # One read of the original deterministic identity can prove
                    # a lost acknowledgement. It never permits another POST.
        saved = attempt['root_conversation']
        require(saved['plan'] == plan and saved.get('creation_reserved'),
                'review_conversation_identity_mismatch')
        value = self.original.data(self.original.request(route + '/' + cid +
            '?agent_id=' + AGENT + '&agent_workspace_id=' + WORKSPACE))
        require(value.get('id') == cid and value.get('workspace_id') == WORKSPACE and
                value.get('agent_workspace_id') == WORKSPACE and value.get('agent_id') == AGENT and
                not value.get('parent_conversation_id') and value.get('status') == 'active',
                'review_conversation_not_parentless_authorized')
        saved['verified'] = True
        self.job.journal.save()
        self.job.store(self.repo + '/' + self.phase + '/attempt-' + str(attempt['number']) +
                       '-conversation.json', value)
        return cid

    def rpc(self, method, params, rid):
        if method != 'message/send':
            return self.original.rpc(method, params, rid)
        require(params.get('model') == 'kimi-k3' and params.get('idempotencyKey') == rid and
                params.get('message', {}).get('messageId') == rid and
                not params['message'].get('contextId') and not params['message'].get('taskId'),
                'review_new_request_identity_invalid')
        saved = self.job.state['model_tasks'][self.repo + '_' + self.phase]
        attempt = saved['attempts'][-1]
        require(attempt['request_id'] == rid and not attempt.get('task_id') and
                not attempt.get('submission_reserved'), 'review_submission_read_original_only')
        cid = self.conversation(attempt)
        request = copy.deepcopy(params)
        request['message']['contextId'] = cid
        self.job.store(self.repo + '/' + self.phase + '/attempt-' +
                       str(attempt['number']) + '-request.json', request)
        attempt['submission_reserved'] = True
        attempt['request_sha256'] = hashlib.sha256(
            json.dumps(request, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        self.job.journal.save()
        result = self.original.rpc(method, request, rid)
        suffix = hashlib.sha256((WORKSPACE + '\x00' + rid).encode()).hexdigest()[:48]
        require(result.get('id') == 'art-' + suffix and
                result.get('metadata', {}).get('manifestId') == 'arm-' + suffix,
                'review_created_task_identity_mismatch')
        return result


class ReviewJob:
    def __init__(self, job, repo, phase):
        self.original = job
        self.api = ReviewAPI(job, repo, phase)

    def __getattr__(self, name):
        return getattr(self.original, name)


def run_isolated_review(job, repo, phase, context, prompt, parser, **kwargs):
    # A legacy pending submission is recovered by its original request identity;
    # an existing failed auth task remains terminal and is never replaced here.
    kwargs['recover_pending_submission'] = True
    return run_review(ReviewJob(job, repo, phase), repo, phase, context, prompt, parser, **kwargs)


def probe(api, objects, date, run_id):
    """Exercise the real code/API call sites on one already accepted snapshot.

    Separate maintenance journal; no new repository acquisition, daily pointer,
    publication, knowledge registration, or group send.
    """
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    from cloud_daily import Journal
    from daily_delivery import read_json
    from api_port_review import Job, review_repository as api_review
    from source_code_review import review_repository as code_review
    import os
    from cloud_preflight import GitHub, REPOSITORIES
    github = GitHub(os.environ['SCAN_GITHUB_TOKEN'])
    access=[]
    for repo in REPOSITORIES:
        value=github.get(repo.owner+'/'+repo.name,'/branches/'+repo.branch)
        commit=value['commit']['sha']
        require(len(commit)==40 and all(c in '0123456789abcdef' for c in commit),
                'maintenance_github_branch_identity_invalid')
        access.append(repo.name)
    pointer = read_json(objects, 'daily/' + date.replace('-','') + '/ready.json', missing=True)
    if pointer is None:
        return dict(review_conversation_check_available=False, no_group_send=True)
    root = read_json(objects, pointer['prefix'] + '/checkpoint.json')
    require(root['date'] == date and root['commits'] == pointer['commits'],
            'maintenance_review_source_identity_mismatch')
    prefix = 'receipts/' + date.replace('-','') + '/review-conversation-check-' + run_id
    journal = Journal(objects, prefix + '/checkpoint.json',
        dict(date=date,scope='review-conversation-check',run_id=run_id,prefix=prefix,
             commits=root['commits'],issues=[]))
    job = Job(api, objects, journal, Path('out/review-conversation-maintenance'))
    proof = root['archives']['matrixone']
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fn,job,'matrixone',proof) for fn in (code_review,api_review)]
        results = [f.result() for f in futures]
    roots=[]
    for value in journal.value['model_tasks'].values():
        require(value.get('status')=='completed', 'maintenance_review_task_incomplete')
        for attempt in value['attempts']:
            item=attempt.get('root_conversation',{})
            require(item.get('verified') and not item['plan']['parent_conversation_id']
                    and attempt.get('submission_reserved'), 'maintenance_review_root_not_verified')
            roots.append(item['plan']['conversation_id'])
    require(len(roots)>=4 and len(roots)==len(set(roots)), 'maintenance_review_roots_not_unique')
    require(all(v['commit']==proof['commit'] for v in results), 'maintenance_review_commit_mismatch')
    return dict(review_conversation_check_available=True, github_scan_token_repositories_verified=access,
                review_parentless_conversations_verified=True,
                review_conversation_count=len(roots), review_code_and_api_two_rounds_verified=True,
                review_conversation_check_prefix=prefix, original_daily_unchanged=True, no_group_send=True)
