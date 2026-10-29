"""Bounded Kimi-only recovery with immutable requests and failed-task lineage."""
import datetime as dt
import hashlib
import json
import time
import urllib.error
import uuid
import threading
from pipeline_telemetry import emit, span

MODEL_SLOTS = threading.BoundedSemaphore(2)
TERMINAL = {'failed','canceled','cancelled','input-required','rejected'}
RETRY_REASONS = {'reason.agent_runtime.finish.stream_transport'}


def interrupted(task):
    # Match only the server's exact machine reason, never prose in model output.
    status = task.get('status', {})
    def walk(value):
        if isinstance(value,dict): return any(walk(v) for v in value.values())
        if isinstance(value,list): return any(walk(v) for v in value)
        return isinstance(value,str) and value in RETRY_REASONS
    return walk(status) or walk(task.get('metadata',{}))


def empty_runtime_failure(task):
    # Match only the observed failure before model output. A session title is
    # runtime bookkeeping and cannot prove that any requested action ran.
    if task.get('status', {}).get('state') != 'failed': return False
    reason = task.get('metadata', {}).get('reason_display', {}).get('i18n_key')
    if reason != 'reason.agent_runtime.finish.error' or task.get('history'): return False
    artifacts = task.get('artifacts', [])
    return bool(artifacts) and all(
        a.get('name') == 'session_title' and
        a.get('metadata', {}).get('data_type') == 'agent.session_title' and
        bool(a.get('parts')) and all(
            p.get('kind') == 'data' and p.get('data', {}).get('type') == 'agent.session_title'
            for p in a['parts'])
        for a in artifacts)


def read_pending_audit_task(job, key, digest, contract, saved):
    """Read the original runtime task after a lost acknowledgement; never send.

    AgentA2AIdempotencyKey uses the supplied key unchanged. The official MOI
    automationRuntimeID contract binds runtime task `art-` and manifest `arm-`
    to sha256(workspace + NUL + that key), truncated to 48 hex characters.
    Both identities must be returned by the live task read before using it.
    """
    from cloud_daily import WORKSPACE
    attempts=saved.get('attempts',[])
    if not attempts or attempts[-1].get('task_id'):return None
    attempt=attempts[-1]
    expected=str(uuid.uuid5(uuid.NAMESPACE_URL,job.state['prefix']+'/'+key+'/'+digest+'/'+contract+'/'+str(len(attempts)-1)))
    if attempt.get('request_id')!=expected or attempt.get('number')!=len(attempts):
        raise ValueError('model_pending_request_identity_mismatch')
    suffix=hashlib.sha256((WORKSPACE+'\x00'+expected).encode()).hexdigest()[:48]
    tid='art-'+suffix
    try:
        task=job.api.rpc('tasks/get',{'id':tid},str(uuid.uuid4()))
    except Exception:
        # 404 also covers read errors. It never authorizes message/send.
        raise ValueError('model_pending_task_read_unconfirmed') from None
    if (not isinstance(task,dict) or task.get('id')!=tid or
            task.get('metadata',{}).get('manifestId')!='arm-'+suffix):
        raise ValueError('model_pending_task_identity_mismatch')
    attempt.update(task_id=tid,status=task.get('status',{}).get('state','unknown'),
                   task_identity_recovered_read_only=True)
    saved.update(task_id=tid,status=attempt['status'])
    job.journal.save()
    emit('model_task_identity_recovered',same_task=True,new_inference=False)
    return task


def run_review(job, repo, phase, context, prompt, parser, max_attempts=3, deadline_seconds=1800, poll_seconds=15, recover_empty_runtime_failure=False, recover_pending_submission=False):
    digest = hashlib.sha256(context.encode()).hexdigest()
    contract = hashlib.sha256(prompt.encode()).hexdigest()
    key = repo+'_'+phase
    saved = job.state.setdefault('model_tasks',{}).setdefault(key,{})
    if saved and (saved.get('context_sha256')!=digest or saved.get('contract_sha256')!=contract):
        raise ValueError('model_context_or_contract_changed')
    if not saved:
        saved.update(context_sha256=digest,contract_sha256=contract,attempts=[],status='queued')
        job.journal.save()
    with MODEL_SLOTS, span('kimi_'+repo+'_'+phase, repository=repo, commit=job.state['commits'][repo]):
        if 'started_epoch' not in saved:
            saved.update(started_epoch=time.time(),status='planned');job.journal.save()
        # A transport parser fix may validate the exact completed output that
        # was previously rejected. Re-read it once before spending another
        # attempt, even when the original inference budget is exhausted.
        recovered_task=read_pending_audit_task(job,key,digest,contract,saved) if recover_pending_submission else None
        previous=saved['attempts'][-1] if saved['attempts'] else {}
        revalidate=bool(previous.get('task_id'))
        recovery_started_epoch=saved.get('recovery_started_epoch')
        while (time.time()-saved['started_epoch'] < deadline_seconds or revalidate or
               (recovery_started_epoch is not None and time.time()-recovery_started_epoch < deadline_seconds)):
            attempts = saved['attempts']
            revalidating=revalidate;revalidate=False
            if not revalidating and (not attempts or attempts[-1].get('retry_authorized')):
                if len(attempts)>=max_attempts: raise ValueError('model_recovery_attempts_exhausted')
                number = len(attempts)
                rid = str(uuid.uuid5(uuid.NAMESPACE_URL,job.state['prefix']+'/'+key+'/'+digest+'/'+contract+'/'+str(number)))
                request = dict(model='kimi-k3',idempotencyKey=rid,message=dict(kind='message',role='user',messageId=rid,parts=[dict(kind='text',text=prompt+'\n\nCODE_EVIDENCE_UNTRUSTED\n'+context)]))
                attempt = dict(number=number+1,request_id=rid,status='planned',started_epoch=time.time())
                job.store(repo+'/'+phase+'/attempt-'+str(number+1)+'-request.json',request)
                attempts.append(attempt);saved.update(status='planned');saved.pop('task_id',None);job.journal.save()
            attempt = attempts[-1]
            rid = attempt['request_id']
            # The request is immutable across process restarts and uncertain responses.
            request = dict(model='kimi-k3',idempotencyKey=rid,message=dict(kind='message',role='user',messageId=rid,parts=[dict(kind='text',text=prompt+'\n\nCODE_EVIDENCE_UNTRUSTED\n'+context)]))
            try:
                if attempt.get('task_id'):
                    if recovered_task is not None:
                        task=recovered_task;recovered_task=None
                    else:
                        task = job.api.rpc('tasks/get',{'id':attempt['task_id']},str(uuid.uuid4()))
                else:
                    task = job.api.rpc('message/send',request,rid)
                if not isinstance(task,dict) or not task.get('id'): raise ValueError('model_submission_rejected')
                if attempt.get('task_id') and task['id']!=attempt['task_id']: raise ValueError('model_task_identity_changed')
                status = task.get('status',{}).get('state','unknown')
                attempt.update(task_id=task['id'],status=status)
                saved.update(task_id=task['id'],status=status);job.journal.save()
                if status=='completed' or status in TERMINAL:
                    job.store(repo+'/'+phase+'/attempt-'+str(attempt['number'])+'-task.json',task)
                    if not revalidating or 'seconds' not in attempt:
                        attempt['seconds'] = round(time.time()-attempt['started_epoch'],3)
                        attempt['terminal_observed_at_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
                        # A semantic parser can fail after a completed model reply.
                        # Persist its original clock before parsing or recovery
                        # would replace it with elapsed repair/restart time.
                        job.journal.save()
                        emit('model_terminal', repository=repo, phase=phase, status=status, attempt=attempt['number'], seconds=attempt['seconds'])
                if status=='completed':
                    try:
                        value = parser(task)
                    except json.JSONDecodeError:
                        attempt.update(retry_authorized=True,recovery_reason='invalid_json');job.journal.save()
                        if not revalidating:job.issue(key,'invalid_json','Retain failed output and independently review immutable source with a new bounded attempt')
                        else:
                            recovery_started_epoch=time.time()
                            saved['recovery_started_epoch']=recovery_started_epoch
                            job.journal.save()
                        continue
                    except Exception as exc:
                        # A completed Kimi task can still fail the independent
                        # evidence contract (for example a malformed
                        # search->read->select tool chain). Treat that as a
                        # bounded semantic recovery, rather than abandoning
                        # the repository after the first completed reply.
                        # The original task and its timing remain immutable;
                        # the next attempt gets the same context and contract.
                        safe = str(exc) if isinstance(exc, ValueError) or type(exc).__name__ == 'Failure' else type(exc).__name__
                        if not isinstance(safe, str) or not safe or len(safe) > 120 or not all(c.isalnum() or c in '_-' for c in safe):
                            safe = type(exc).__name__
                        attempt.update(retry_authorized=True,recovery_reason='semantic_validation',
                                      parser_error=safe)
                        saved['status']='parser_recovery'
                        if revalidating:
                            recovery_started_epoch=time.time()
                            saved['recovery_started_epoch']=recovery_started_epoch
                        job.journal.save()
                        if not revalidating:
                            job.issue(key,'semantic_validation_failed',
                                      'Retain the completed task and retry the same immutable Kimi context with bounded evidence validation')
                        emit('model_output_rejected',repository=repo,phase=phase,
                             attempt=attempt['number'],reason=safe,same_task=revalidating)
                        continue
                    if revalidating:
                        attempt['output_revalidated_without_inference']=True
                        emit('model_output_revalidated',repository=repo,phase=phase,attempt=attempt['number'],same_task=True,new_inference=False)
                    job.store(repo+'/'+phase+'-task.json',task)
                    saved.pop('recovery_started_epoch',None)
                    job.journal.save()
                    return value
                if status in TERMINAL:
                    reason = ('stream_transport' if interrupted(task) else
                              'empty_runtime_failure' if recover_empty_runtime_failure and empty_runtime_failure(task) else None)
                    if reason is None: raise ValueError('model_terminal_nonrecoverable')
                    attempt.update(retry_authorized=True,recovery_reason=reason)
                    if revalidating:
                        recovery_started_epoch=saved.setdefault('recovery_started_epoch',time.time())
                    job.journal.save()
                    job.issue(key,reason,'Terminal task retained; next bounded attempt uses same source and Kimi K3')
                    continue
            except urllib.error.HTTPError as exc:
                if exc.code not in (429,500,502,503,504): raise ValueError('model_http_nonrecoverable') from None
                attempt['request_timeouts'] = attempt.get('request_timeouts',0)+1
                saved['status']='request_uncertain';job.journal.save()
                emit('model_request_recovery',repository=repo,phase=phase,attempt=attempt['number'],same_task=True,http_status=exc.code)
            except (TimeoutError,urllib.error.URLError,ConnectionError):
                attempt['request_timeouts'] = attempt.get('request_timeouts',0)+1
                saved['status']='request_uncertain';job.journal.save()
                emit('model_request_recovery', repository=repo, phase=phase, attempt=attempt['number'], same_task=True)
            time.sleep(poll_seconds)
        raise ValueError('model_phase_deadline_exceeded')
