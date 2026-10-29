"""Serialized, source-identity based ingestion and actual read-only tool evidence."""
import json
import datetime as dt
import re
import threading
import time
import urllib.error
import urllib.parse
import uuid
from pipeline_telemetry import emit,span

KB_LOCK=threading.RLock()
# Binding confirmed by pipeline-repair-20261028's file-executions/retry proof.
# Do not retry another workflow merely because it also processed the same file.
KB_WORKFLOW_ID='kb-rag-workflow-27cf84dc519c77e1fb2659e8'
WORKFLOWS='/workflow/v2/workflow-apps'
EXECUTION_ACTIVE={'preparing','waiting','pending','triggered','running','submitted',
                  'scheduled','queued','paused','cancelling','canceling'}
EXECUTION_SUCCESS={'completed','success','succeeded'}


def transient(exc):
    statuses=('moi_http_429','moi_http_500','moi_http_502','moi_http_503','moi_http_504')
    if isinstance(exc,urllib.error.HTTPError):return exc.code in (429,500,502,503,504)
    return isinstance(exc,(TimeoutError,urllib.error.URLError,ConnectionError)) or str(exc) in statuses


def fact_timeout(deadline):
    if deadline is None:return 90
    remaining=deadline-time.time()
    if remaining<=0:raise ValueError('knowledge_ingestion_deadline')
    return min(90,remaining)


def execution_pages(job,deadline=None):
    # Small official offset pages avoid the observed 100-row backend timeout.
    seen=set();expected_total=None
    for offset in range(0,10000,10):
        data=job.api.data(job.api.request(WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions?'+
                                        urllib.parse.urlencode(dict(offset=offset,limit=10)),
                                        timeout=min(15,fact_timeout(deadline))))
        values=data.get('executions',[]);total=data.get('total')
        if (not isinstance(values,list) or len(values)>10
                or any(not isinstance(v,dict) or not v.get('execution_id') for v in values)
                or type(total) is not int or total<offset+len(values)):
            raise ValueError('knowledge_execution_list_invalid')
        if expected_total is not None and total!=expected_total:
            raise ValueError('knowledge_execution_list_changed')
        expected_total=total
        ids=[v['execution_id'] for v in values]
        if len(set(ids))!=len(ids) or seen.intersection(ids):
            raise ValueError('knowledge_execution_list_changed')
        seen.update(ids)
        yield values
        if offset+len(values)>=total:return
        if len(values)!=10:raise ValueError('knowledge_execution_list_incomplete')
    raise ValueError('knowledge_execution_list_incomplete')


def execution_facts(job,fid,deadline=None):
    # Verified in the archived workflow.go ListFileExecutions handler: file_id
    # is the query parameter; summaries intentionally do not expose dispatch IDs.
    try:
        data=job.api.data(job.api.request(WORKFLOWS+'/file-executions?'+urllib.parse.urlencode({'file_id':fid}),timeout=min(15,fact_timeout(deadline))))
    except Exception as exc:
        if not transient(exc):raise
        # A failed diagnostic read never means no execution exists. Read every
        # small page before using the same-file facts to authorize recovery.
        emit('knowledge_execution_small_page_fallback',same_sources=True)
        facts=[v for page in execution_pages(job,deadline) for v in page
               if v.get('file_id')==fid and v.get('workflow_id')==KB_WORKFLOW_ID]
        return facts
    facts=data.get('executions',[])
    if (not isinstance(facts,list) or any(not isinstance(v,dict) for v in facts)
            or data.get('total',len(facts))!=len(facts)):
        raise ValueError('knowledge_file_execution_facts_invalid')
    for fact in facts:
        if fact.get('file_id',fid)!=fid:
            raise ValueError('knowledge_file_execution_identity_mismatch')
    return [v for v in facts if v.get('workflow_id')==KB_WORKFLOW_ID]


def execution_dispatch(job,fid,eid,deadline=None):
    # workflow.go workflowPagination uses offset/limit (not page/page_size).
    # execution.go ExecutionListItem exposes both file_id and dispatch_job_id;
    # GetExecution deliberately strips dispatch_job_id and cannot supply it.
    for values in execution_pages(job,deadline):
        selected=[v for v in values if v.get('execution_id')==eid]
        if selected:
            if len(selected)!=1:raise ValueError('knowledge_execution_identity_mismatch')
            value=selected[0]
            if (value.get('workflow_id')!=KB_WORKFLOW_ID or value.get('file_id')!=fid
                    or value.get('execution_mode')!='volume_trigger'
                    or not value.get('dispatch_job_id')):
                raise ValueError('knowledge_execution_identity_mismatch')
            return value
    raise ValueError('knowledge_execution_dispatch_unavailable')


def lineage_request_id(job,fid,eid):
    return str(uuid.uuid5(uuid.NAMESPACE_URL,job.state['prefix']+'/80001/'+fid+'/'+eid+'/lineage-1'))


def recover_lineage(job,fid,state,allow_retry=True):
    from knowledge_save_recovery import recover_save_node, sink_failure
    deadline=state['ingestion_deadline_epoch'] if allow_retry else None
    if state.get('save_node_recovery'):
        return recover_save_node(job,fid,state,deadline=deadline)
    facts=execution_facts(job,fid,deadline)
    recovery=state.get('lineage_recovery')
    if recovery:
        original=recovery['original_execution']
        if (recovery.get('attempts')!=1 or original.get('workflow_id')!=KB_WORKFLOW_ID
                or recovery.get('file_id')!=fid
                or recovery.get('request_id')!=lineage_request_id(job,fid,original['execution_id'])):
            raise ValueError('knowledge_lineage_checkpoint_identity_mismatch')
        if recovery['status']=='blocked':
            if recovery.get('failure_reason')=='retry_execution_failed':raise ValueError('knowledge_lineage_retry_exhausted')
            raise ValueError('knowledge_lineage_retry_blocked')
        if recovery['status'] not in ('accepted','submission_unknown'):
            raise ValueError('knowledge_lineage_checkpoint_identity_mismatch')
        # A reservation is consumed even if a process died before POST. After
        # any uncertain submission only read original file facts; never replay
        # POST or append/select/reconcile to conceal the missing acknowledgement.
        newer=[v for v in facts if v.get('execution_id') not in recovery['prior_execution_ids']]
        if len(newer)>1:raise ValueError('knowledge_lineage_recovery_ambiguous')
        if newer:
            value=newer[0];dispatch=execution_dispatch(job,fid,value['execution_id'],deadline)
            if (dispatch.get('status')!=value.get('status')
                    or recovery.get('dispatch_job_id',dispatch['dispatch_job_id'])!=dispatch['dispatch_job_id']):
                raise ValueError('knowledge_lineage_recovery_identity_mismatch')
            recovery.update(new_execution=dict(value),new_dispatch_job_id=dispatch['dispatch_job_id'],
                            correlation='acknowledged_dispatch' if recovery.get('dispatch_job_id') else 'same_file_observation')
            if value.get('status') not in EXECUTION_ACTIVE|EXECUTION_SUCCESS:
                recovery.update(status='blocked',failure_reason='retry_execution_failed');job.journal.save()
                raise ValueError('knowledge_lineage_retry_exhausted')
            job.journal.save()
        return True
    if not allow_retry or not facts:return False
    # FileExecutions returns newest first. Any active same-file execution is
    # sufficient to prohibit a retry, including while sources still says failed.
    if any(v.get('status') in EXECUTION_ACTIVE for v in facts):return True
    latest=facts[0]
    if latest.get('status') in EXECUTION_SUCCESS:return True
    if latest.get('status')=='failed' and sink_failure(latest.get('error')):
        return recover_save_node(job,fid,state,latest,deadline)
    error=re.fullmatch(r'\[moi:data\.lineage\.register\] register lineage for source_file_id '+
                       re.escape(fid)+r': \[1\] Internal Server Error \(request_id: ([0-9a-f-]{36})\)',latest.get('error') or '')
    if latest.get('status')!='failed' or latest.get('execution_mode')!='volume_trigger' or not error:
        raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
    original=execution_dispatch(job,fid,latest['execution_id'],deadline)
    if original.get('status')!='failed' or original.get('error')!=latest['error']:
        raise ValueError('knowledge_execution_identity_mismatch')
    if time.time()>=state['ingestion_deadline_epoch']:raise ValueError('knowledge_ingestion_deadline')
    rid=lineage_request_id(job,fid,latest['execution_id'])
    request=dict(source_dispatch_job_id=original['dispatch_job_id'],execution_ids=[latest['execution_id']],
                 all_failed=False,request_id=rid)
    recovery=dict(attempts=1,file_id=fid,request_id=rid,request=request,
                  original_execution=dict(latest),original_dispatch_job_id=original['dispatch_job_id'],
                  failure_request_id=error[1],prior_execution_ids=[v['execution_id'] for v in facts],
                  status='submission_unknown',reserved_epoch=time.time())
    state['lineage_recovery']=recovery
    try:
        job.journal.save()
    except Exception:
        # PUT may have committed despite a failed readback. Keep the reservation
        # in memory too; sacrificing this attempt is safer than a second POST.
        raise ValueError('knowledge_lineage_checkpoint_unconfirmed') from None
    if time.time()>=state['ingestion_deadline_epoch']:raise ValueError('knowledge_ingestion_deadline')
    timeout=fact_timeout(deadline)
    try:
        answer=job.api.data(job.api.request(WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions/batch-retry',
                                            request,method='POST',timeout=timeout))
    except Exception as exc:
        if transient(exc):
            emit('knowledge_lineage_submission_unknown',same_sources=True,attempts=1)
            return True
        recovery.update(status='blocked',error_type=type(exc).__name__);job.journal.save()
        raise ValueError('knowledge_lineage_retry_rejected') from None
    if (answer.get('source_dispatch_job_id')!=original['dispatch_job_id']
            or type(answer.get('accepted_count')) is not int or answer['accepted_count']!=1
            or not answer.get('dispatch_job_id') or answer['dispatch_job_id']==original['dispatch_job_id']
            or type(answer.get('replayed')) is not bool
            or answer.get('status') not in ('waiting','pending','running','completed')):
        recovery['status']='blocked';job.journal.save()
        raise ValueError('knowledge_lineage_retry_response_invalid')
    recovery.update(status='accepted',response=answer,dispatch_job_id=answer['dispatch_job_id'])
    job.journal.save()
    emit('knowledge_lineage_retry_accepted',same_sources=True,attempts=1)
    return True


def rows(api):
    values=[]
    for page in range(1,101):
        data=api.data(api.request('/semantic-models/80001/sources?page='+str(page)+'&page_size=100',timeout=90))
        current=data.get('items',data.get('sources',[]));values.extend(current)
        if len(current)<100:return values
    raise ValueError('knowledge_pagination_incomplete')


def matching(allrows,fid):
    return [r for r in allrows if fid in (r.get('source_file_id'),r.get('kb_file_id'),r.get('source_id'))]


def ensure_sources(job,artifacts,deadline_seconds=1800,poll_seconds=15,runtime_visibility_grace_seconds=600,registration_volume_id=None):
    with KB_LOCK,span('knowledge_ingestion'):
        saved=job.state.setdefault('knowledge_registration',{})
        start=time.monotonic();seen_rounds={};last_reconcile=start-60
        pending_fids={a['file_id'] for a in artifacts}
        # Same batch/FID retains its original budget across process resumes.
        # Always inspect succeeded sources before enforcing a historical deadline.
        new_budget=False
        for artifact in artifacts:
            state=saved.setdefault(artifact['file_id'],{})
            if 'ingestion_deadline_epoch' not in state:
                first=min([time.time()]+[state[k] for k in ('missing_runtime_first_observed_epoch','active_dispatch_first_observed_epoch') if k in state])
                state['ingestion_deadline_epoch']=first+deadline_seconds;new_budget=True
        if new_budget:job.journal.save()
        while time.monotonic()-start<deadline_seconds:
            operation='source_inventory'
            try:
                inventory=rows(job.api);ready=True
                pending_fids={a['file_id'] for a in artifacts
                              if not any(v.get('ingest_status')=='succeeded' for v in matching(inventory,a['file_id']))}
                for artifact in artifacts:
                    fid=artifact['file_id'];found=matching(inventory,fid)
                    # Detect and retain duplicates; never add another copy to mask failed ingestion.
                    if len(found)>1:emit('knowledge_duplicate_source',count=len(found))
                    if any(v.get('ingest_status')=='succeeded' for v in found):
                        state=saved[fid]
                        recovery=state.get('lineage_recovery') or state.get('save_node_recovery')
                        if recovery and not recovery.get('source_succeeded'):
                            # Success is an actual source fact, even if recovery
                            # metadata is still unavailable or its clock expired.
                            try:recover_lineage(job,fid,state,allow_retry=False)
                            except Exception:emit('knowledge_lineage_success_metadata_unavailable',same_sources=True)
                            recovery['source_succeeded']=True
                        saved.setdefault(fid,{})['succeeded']=True;continue
                    ready=False;state=saved.setdefault(fid,{})
                    if time.time()>=state['ingestion_deadline_epoch']:
                        raise ValueError('knowledge_ingestion_deadline')
                    if state.get('lineage_recovery') or state.get('save_node_recovery') or (not found and state.get('observed')):
                        operation='file_execution_facts'
                        recover_lineage(job,fid,state)
                        continue
                    if found:
                        state['observed']=True
                        if all(v.get('ingest_status')=='failed' for v in found):
                            if not state.get('failure_evidence_recorded'):
                                state['failure_evidence']=job.store('knowledge-failure-'+fid+'.json',found)
                                # Retain the first failed view unchanged throughout recovery.
                                state['failure_evidence_recorded']=True
                                job.journal.save()
                            operation='source_jobs'
                            jobs=job.api.data(job.api.request('/semantic-models/80001/source-jobs',timeout=90))
                            active=[v for v in jobs.get('items',[]) if fid in (v.get('source_file_id'),v.get('kb_file_id')) and v.get('job_status') in ('pending','queued','running')]
                            if not active:
                                operation='file_execution_facts'
                                if any(v.get('source_file_id')!=fid or v.get('kb_file_id',fid)!=fid for v in found):
                                    raise ValueError('knowledge_source_identity_mismatch')
                                if recover_lineage(job,fid,state):continue
                                # The live source view can briefly project a missing execution
                                # before its real file-runtime facts are visible. Re-observe
                                # these exact source IDs only; never reappend or accept failure.
                                invisible=all(re.fullmatch(r'workflow execution [0-9a-f-]{36} not found: domain object not found',v.get('error') or '') for v in found)
                                dispatch_busy=all(re.fullmatch(r'workflow has an active volume dispatch job: job [0-9a-f-]{36} status (?:pending|queued|running)',v.get('error') or '') for v in found)
                                field='active_dispatch' if dispatch_busy else 'missing_runtime'
                                first=state.setdefault(field+'_first_observed_epoch',time.time()) if invisible or dispatch_busy else 0
                                elapsed=time.time()-first
                                if not (invisible or dispatch_busy) or elapsed>=runtime_visibility_grace_seconds:
                                    raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
                                state[field+'_observations']=state.get(field+'_observations',0)+1
                                job.journal.save()
                                emit('knowledge_runtime_visibility_wait',same_sources=True,projection_reason=field,elapsed_seconds=round(elapsed,3),grace_seconds=runtime_visibility_grace_seconds)
                            else:emit('knowledge_status_reconciling',active_jobs=len(active))
                    else:
                        seen_rounds[fid]=seen_rounds.get(fid,0)+1
                        # Native raw-volume save may enqueue registration. Let it become visible first.
                        if seen_rounds[fid]>=3 and not state.get('append_attempted') and not state.get('observed'):
                            state['append_attempted']=True
                            try:
                                job.journal.save()
                            except Exception:
                                # No registration request was reached. A failed checkpoint
                                # acknowledgement must not become a false submission claim.
                                state.pop('append_attempted',None)
                                emit('knowledge_registration_preflight_failed',request_sent=False)
                                raise
                            operation='source_registration'
                            job.api.request('/semantic-models/80001/sources',{'sources':[dict(source_type='local_file',upload_kind='unstructured',file_id=fid,file_name=artifact['name'])]},timeout=90)
                        elif state.get('append_attempted') and time.monotonic()-start>300 and not state.get('observed'):
                            if not registration_volume_id or state.get('selection_recovery_attempted'):
                                raise ValueError('knowledge_registration_uncertain_no_resubmit')
                            # The supported selection path checks persistent source facts
                            # and skips existing file IDs before append. Never replay the
                            # original uncertain local_file mutation or create another file.
                            selection=dict(kind='volume_files',volume_id=registration_volume_id,all_selected=False,selected_file_ids=[fid])
                            operation='source_selection_preview'
                            preview=job.api.data(job.api.request('/semantic-models/80001/source-selections/preview',{'source_selections':[selection]},method='POST',timeout=90))
                            if preview==dict(file_count=0,table_count=0,total_count=0):
                                emit('knowledge_source_fact_exists_waiting',same_sources=True)
                            elif preview==dict(file_count=1,table_count=0,total_count=1):
                                state['selection_recovery_attempted']=True
                                try:
                                    job.journal.save()
                                except Exception:
                                    state.pop('selection_recovery_attempted',None)
                                    emit('knowledge_registration_preflight_failed',request_sent=False)
                                    raise
                                operation='source_registration'
                                job.api.request('/semantic-models/80001/sources',{'source_selections':[selection]},method='POST',timeout=90)
                                emit('knowledge_missing_registration_recovered',same_sources=True,volume_id=registration_volume_id)
                            else:
                                raise ValueError('knowledge_registration_preview_identity_invalid')
                job.journal.save()
                if ready:return
                if not any(v.get('lineage_recovery') or v.get('save_node_recovery') for v in saved.values()) and time.monotonic()-last_reconcile>=60:
                    operation='source_jobs'
                    jobs=job.api.data(job.api.request('/semantic-models/80001/source-jobs',timeout=90))
                    # A conflict is an uncertain dispatch; cool down before observing again.
                    last_reconcile=time.monotonic()
                    if jobs.get('reconcile_required'):
                        operation='source_jobs_reconcile'
                        job.api.request('/semantic-models/80001/source-jobs/reconcile',{},method='POST',timeout=90)
                    emit('knowledge_waiting',sources=len(artifacts))
            except Exception as exc:
                conflict=str(exc)=='moi_http_409' and operation in ('source_registration','source_jobs_reconcile')
                if conflict:
                    job.state.setdefault('knowledge_conflicts',[]).append(dict(operation=operation,http_status=409,at_utc=dt.datetime.now(dt.timezone.utc).isoformat()))
                    job.journal.save()
                    emit('knowledge_dispatch_conflict',operation=operation,http_status=409,same_sources=True)
                if not (conflict or transient(exc)):raise
                # Re-observe the same source/jobs after an uncertain append or reconcile.
                # Persisted append_attempted prevents replaying a source registration.
                emit('knowledge_read_recovery',same_sources=True,error_type=type(exc).__name__)
            if any(time.time()>=saved[fid]['ingestion_deadline_epoch'] for fid in pending_fids):
                raise ValueError('knowledge_ingestion_deadline')
            time.sleep(poll_seconds)
        raise ValueError('knowledge_ingestion_deadline')


def audit(job,targets,label):
    from cloud_daily import verify_rag
    from kimi_recovery import run_review
    from api_port_review import llm_calls
    repo=sorted(job.state['commits'])[0]
    prompt='mode=audit。只执行只读知识库验收，不扫描、不审代码、不修改文件、不上传、不发消息。必须实际调用search_rag_chunks，以每个精确file_id检索marker，max_hits=1,max_rows=1。若返回完整未截断的content_preview，直接核对marker；若返回工具摘要或截断预览，必须实际调用read_artifact，使用该次search返回的artifact_id、精确file_id、chunk_id、semantic_model_id=80001、cursor=0读取完整chunk，确认has_more=false且全文包含marker。然后实际调用select_final_sources，选择同一file_id、chunk_id和artifact_id，必须返回accepted=true。摘要、文件名或助手叙述不能替代真实正文与最终来源选择。'
    # A semantic model ID is not a Catalog volume ID. The optional volume
    # filter silently excludes every source when the two are confused.
    prompt+='\n知识库semantic_model_id为80001；它不是volume_id。search_rag_chunks必须省略volume_id，只传file_ids=[目标file_id]、keywords=[目标marker]、max_hits=1、max_rows=1。禁止把80001填入volume_id。read_artifact才使用semantic_model_id=80001。按目标依次完成search→完整read→select；零命中立即结束并如实报告失败，不循环猜测编号或等待。完成工具核验后立即结束，不需要长篇解释。'
    legacy_phase='kb_'+label+'_scope_v2'
    # Existing requests keep their exact immutable v2 prompt and context. Only
    # new phases get the unambiguous final-source-set contract.
    legacy=repo+'_'+legacy_phase in job.state.get('model_tasks',{})
    phase=legacy_phase if legacy else 'kb_'+label+'_scope_v3'
    if not legacy:
        prompt=prompt.replace('然后实际调用select_final_sources，选择同一file_id、chunk_id和artifact_id，必须返回accepted=true。',
                              '记录每个目标核实后的file_id、chunk_id和artifact_id。')
        prompt=prompt.replace('按目标依次完成search→完整read→select；',
                              '按目标依次完成search→必要时完整read；全部目标均已核实后，只调用一次select_final_sources，sources数组必须同时包含全部目标的准确file_id、chunk_id、artifact_id，必须返回accepted=true。不得分别选择单个目标，也不得在最终汇总选择之后再选择子集；')
    context=json.dumps(targets,sort_keys=True)
    def parser(task):
        calls=llm_calls(task)
        if not calls or any(c.get('model')!='kimi-k3' or c.get('status')!='completed' for c in calls):
            raise ValueError('knowledge_actual_kimi_missing')
        return verify_rag(task,targets)
    # Retain the prior incorrect-scope task and its original inference budget.
    return run_review(job,repo,phase,context,prompt,parser,deadline_seconds=1200,
                      recover_empty_runtime_failure=True,recover_pending_submission=True)
