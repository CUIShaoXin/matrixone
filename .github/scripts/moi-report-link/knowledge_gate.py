"""Serialized, source-identity based ingestion and actual read-only tool evidence."""
import json
import datetime as dt
import re
import threading
import time
import urllib.error
from pipeline_telemetry import emit,span

KB_LOCK=threading.RLock()


def rows(api):
    values=[]
    for page in range(1,101):
        data=api.data(api.request('/semantic-models/80001/sources?page='+str(page)+'&page_size=100',timeout=90))
        current=data.get('items',data.get('sources',[]));values.extend(current)
        if len(current)<100:return values
    raise ValueError('knowledge_pagination_incomplete')


def matching(allrows,fid):
    return [r for r in allrows if fid in (r.get('source_file_id'),r.get('kb_file_id'),r.get('source_id'))]


def ensure_sources(job,artifacts,deadline_seconds=1800,poll_seconds=15,runtime_visibility_grace_seconds=180):
    with KB_LOCK,span('knowledge_ingestion'):
        saved=job.state.setdefault('knowledge_registration',{})
        start=time.monotonic();seen_rounds={};last_reconcile=start-60
        while time.monotonic()-start<deadline_seconds:
            operation='source_inventory'
            try:
                inventory=rows(job.api);ready=True
                for artifact in artifacts:
                    fid=artifact['file_id'];found=matching(inventory,fid)
                    # Detect and retain duplicates; never add another copy to mask failed ingestion.
                    if len(found)>1:emit('knowledge_duplicate_source',count=len(found))
                    if any(v.get('ingest_status')=='succeeded' for v in found):
                        saved.setdefault(fid,{})['succeeded']=True;continue
                    ready=False;state=saved.setdefault(fid,{})
                    if found:
                        state['observed']=True
                        if all(v.get('ingest_status')=='failed' for v in found):
                            if not state.get('failure_evidence_recorded'):
                                state['failure_evidence']=job.store('knowledge-failure-'+fid+'.json',found)
                                # Retain the first failed view unchanged throughout recovery.
                                state['failure_evidence_recorded']=True
                            operation='source_jobs'
                            jobs=job.api.data(job.api.request('/semantic-models/80001/source-jobs',timeout=90))
                            active=[v for v in jobs.get('items',[]) if fid in (v.get('source_file_id'),v.get('kb_file_id')) and v.get('job_status') in ('pending','queued','running')]
                            if not active:
                                # The live source view can briefly project a missing execution
                                # before its real file-runtime facts are visible. Re-observe
                                # these exact source IDs only; never reappend or accept failure.
                                invisible=all(re.fullmatch(r'workflow execution [0-9a-f-]{36} not found: domain object not found',v.get('error') or '') for v in found)
                                first=state.setdefault('missing_runtime_first_observed_epoch',time.time()) if invisible else 0
                                elapsed=time.time()-first
                                if not invisible or elapsed>=runtime_visibility_grace_seconds:
                                    raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
                                state['missing_runtime_observations']=state.get('missing_runtime_observations',0)+1
                                job.journal.save()
                                emit('knowledge_runtime_visibility_wait',same_sources=True,elapsed_seconds=round(elapsed,3),grace_seconds=runtime_visibility_grace_seconds)
                            else:emit('knowledge_status_reconciling',active_jobs=len(active))
                    else:
                        seen_rounds[fid]=seen_rounds.get(fid,0)+1
                        # Native raw-volume save may enqueue registration. Let it become visible first.
                        if seen_rounds[fid]>=3 and not state.get('append_attempted'):
                            state['append_attempted']=True;job.journal.save()
                            operation='source_registration'
                            job.api.request('/semantic-models/80001/sources',{'sources':[dict(source_type='local_file',upload_kind='unstructured',file_id=fid,file_name=artifact['name'])]},timeout=90)
                        elif state.get('append_attempted') and time.monotonic()-start>300 and not state.get('observed'):
                            raise ValueError('knowledge_registration_uncertain_no_resubmit')
                job.journal.save()
                if ready:return
                if time.monotonic()-last_reconcile>=60:
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
                transient=conflict or isinstance(exc,(TimeoutError,urllib.error.URLError,ConnectionError)) or str(exc) in ('moi_http_429','moi_http_500','moi_http_502','moi_http_503','moi_http_504')
                if not transient:raise
                # Re-observe the same source/jobs after an uncertain append or reconcile.
                # Persisted append_attempted prevents replaying a source registration.
                emit('knowledge_read_recovery',same_sources=True,error_type=type(exc).__name__)
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
    context=json.dumps(targets,sort_keys=True)
    def parser(task):
        calls=llm_calls(task)
        if not calls or any(c.get('model')!='kimi-k3' or c.get('status')!='completed' for c in calls):
            raise ValueError('knowledge_actual_kimi_missing')
        return verify_rag(task,targets)
    # Retain the prior incorrect-scope task and its original inference budget.
    return run_review(job,repo,'kb_'+label+'_scope_v2',context,prompt,parser,deadline_seconds=1200)
