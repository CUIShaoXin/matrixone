"""Read actual successful ingestion when the source status projection is stale.

This is a read-only proof, not a source-state repair or a new ingestion budget.
The caller must still run the native retrieval/citation audit for every target.
"""
import datetime as dt
import hashlib
import re
import time
import urllib.parse


def verify(job,artifact,target,found,registration_volume_id):
    from knowledge_gate import KB_WORKFLOW_ID,WORKFLOWS,execution_facts,EXECUTION_ACTIVE,EXECUTION_SUCCESS
    fid=artifact['file_id']
    if (registration_volume_id!=140002 or not target or target.get('file_id')!=fid
            or len(found)!=1 or found[0].get('source_file_id')!=fid
            or found[0].get('kb_file_id')!=fid):return None
    source=found[0];status=source.get('ingest_status')
    if status=='failed':
        if not re.fullmatch(r'workflow execution [0-9a-f-]{36} not found: domain object not found',source.get('error') or ''):return None
    elif status!='pending' or source.get('error'):return None
    # This clock bounds diagnostic GETs only. The original ingestion deadline
    # stays unchanged; no upload, append, retry or reconcile is performed here.
    deadline=time.time()+45
    def read(path):
        remaining=deadline-time.time()
        if remaining<=0:raise ValueError('knowledge_materialization_read_deadline')
        return job.api.data(job.api.request(path,timeout=min(15,remaining),retry=False))
    facts=execution_facts(job,fid,deadline)
    if any(v.get('status') in EXECUTION_ACTIVE for v in facts):return None
    if facts and facts[0].get('status') not in EXECUTION_SUCCESS:return None
    candidates=[v for v in facts if v.get('status') in EXECUTION_SUCCESS
                and v.get('execution_mode')=='volume_trigger'
                and v.get('workflow_id')==KB_WORKFLOW_ID and v.get('file_id',fid)==fid]
    if not candidates:return None
    fact=candidates[0];eid=fact['execution_id'];route=WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions/'+eid
    execution=read(route).get('execution',{})
    inp=execution.get('input_payload',{})
    if (execution.get('execution_id')!=eid or execution.get('workflow_id')!=KB_WORKFLOW_ID
            or execution.get('status') not in EXECUTION_SUCCESS or inp.get('file_id')!=fid
            or inp.get('volume_id')!=registration_volume_id):
        raise ValueError('knowledge_materialization_execution_identity_mismatch')
    node=read(route+'/nodes/root.register_lineage');run=node.get('run',{})
    ni=run.get('runtime_input',{});no=run.get('runtime_output',{})
    if (node.get('node',{}).get('node_key')!='root.register_lineage' or run.get('status')!='COMPLETED'
            or ni.get('source_file_ids')!=[fid] or ni.get('vector_table')!='kb_80001_text_index'
            or not no.get('vector_asset_id')
            or not any(x.get('source_file_id')==fid and x.get('vector_asset_id')==no['vector_asset_id'] for x in no.get('lineages',[]))):
        raise ValueError('knowledge_materialization_lineage_not_complete')
    raw=job.api.file(fid)
    if len(raw)!=artifact['bytes'] or hashlib.sha256(raw).hexdigest()!=artifact['sha256']:
        raise ValueError('knowledge_materialization_file_hash_mismatch')
    marker=target.get('marker','')
    if not marker or marker.encode() not in raw:raise ValueError('knowledge_materialization_marker_mismatch')
    sid=source.get('source_id')
    if not sid:raise ValueError('knowledge_materialization_source_identity_missing')
    document=read('/semantic-models/80001/sources/'+urllib.parse.quote(sid,safe='')+'/document')
    ds=document.get('source',{})
    if (ds.get('model_id')!=80001 or ds.get('source_id')!=sid or ds.get('source_file_id')!=fid
            or ds.get('kb_file_id')!=fid or ds.get('effective_enabled') is not True
            or document.get('preview',{}).get('available') is not True
            or document.get('segment_status',{}).get('available') is not True):
        raise ValueError('knowledge_materialization_document_identity_mismatch')
    segments=document.get('segments',[])
    if not segments or document['segment_status'].get('total')!=len(segments):
        raise ValueError('knowledge_materialization_document_incomplete')
    hits=[s for s in segments if s.get('enabled') is True and marker in s.get('content','')
          and s.get('chunk_id') and str(s.get('metadata',{}).get('volume_id'))==str(registration_volume_id)]
    if not hits:raise ValueError('knowledge_materialization_marker_missing')
    return dict(schema='matrix_actual_kb_materialization_v1',file_id=fid,source_id=sid,
                original_source_projection=status,source_projection_repaired=False,
                execution_id=eid,workflow_id=KB_WORKFLOW_ID,
                artifact_sha256=artifact['sha256'],marker=marker,
                vector_asset_id=no['vector_asset_id'],document_etag=document.get('etag'),
                segment_count=len(segments),marker_chunk_ids=[s['chunk_id'] for s in hits],
                native_retrieval_and_citation_still_required=True,
                checked_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
