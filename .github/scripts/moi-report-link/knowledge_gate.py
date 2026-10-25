"""Serialized, source-identity based ingestion and actual read-only tool evidence."""
import json
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


def ensure_sources(job,artifacts,deadline_seconds=1800,poll_seconds=15):
    with KB_LOCK,span('knowledge_ingestion'):
        saved=job.state.setdefault('knowledge_registration',{})
        start=time.monotonic();seen_rounds={};last_reconcile=0
        while time.monotonic()-start<deadline_seconds:
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
                            job.store('knowledge-failure-'+fid+'.json',found)
                            jobs=job.api.data(job.api.request('/semantic-models/80001/source-jobs',timeout=90))
                            active=[v for v in jobs.get('items',[]) if fid in (v.get('source_file_id'),v.get('kb_file_id')) and v.get('job_status') in ('pending','queued','running')]
                            if not active:raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
                            emit('knowledge_status_reconciling',active_jobs=len(active))
                    else:
                        seen_rounds[fid]=seen_rounds.get(fid,0)+1
                        # Native raw-volume save may enqueue registration. Let it become visible first.
                        if seen_rounds[fid]>=3 and not state.get('append_attempted'):
                            state['append_attempted']=True;job.journal.save()
                            job.api.request('/semantic-models/80001/sources',{'sources':[dict(source_type='local_file',upload_kind='unstructured',file_id=fid,file_name=artifact['name'])]},timeout=90)
                        elif state.get('append_attempted') and time.monotonic()-start>300 and not state.get('observed'):
                            raise ValueError('knowledge_registration_uncertain_no_resubmit')
                job.journal.save()
                if ready:return
                if time.monotonic()-last_reconcile>=60:
                    jobs=job.api.data(job.api.request('/semantic-models/80001/source-jobs',timeout=90))
                    if jobs.get('reconcile_required'):
                        job.api.request('/semantic-models/80001/source-jobs/reconcile',{},method='POST',timeout=90)
                    last_reconcile=time.monotonic();emit('knowledge_waiting',sources=len(artifacts))
            except Exception as exc:
                transient=isinstance(exc,(TimeoutError,urllib.error.URLError,ConnectionError)) or str(exc) in ('moi_http_429','moi_http_500','moi_http_502','moi_http_503','moi_http_504')
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
    prompt='mode=audit。只执行只读知识库验收，不扫描、不审代码、不修改文件、不上传、不发消息。必须实际调用search_rag_chunks，以每个精确file_id检索marker，max_hits=1,max_rows=1，取包含marker的完整content_preview，再实际调用select_final_sources选择这些来源。不要凭文件名或助手叙述断言通过。'
    context=json.dumps(targets,sort_keys=True)
    def parser(task):
        calls=llm_calls(task)
        if not calls or any(c.get('model')!='kimi-k3' or c.get('status')!='completed' for c in calls):
            raise ValueError('knowledge_actual_kimi_missing')
        return verify_rag(task,targets)
    return run_review(job,repo,'kb_'+label,context,prompt,parser,deadline_seconds=1200)
