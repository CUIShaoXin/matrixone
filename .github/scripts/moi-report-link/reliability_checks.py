"""No-send maintenance checks against the day's already accepted KB files."""
from pathlib import Path
import re
import time

from cloud_daily import Journal,require
from daily_delivery import read_json,checked_file
from api_port_review import Job
from knowledge_gate import audit,ensure_sources,execution_pages,EXECUTION_SUCCESS,KB_WORKFLOW_ID


def observed_file_execution(job,fid,deadline):
    # This read-only smoke check needs one matching successful execution, not a
    # complete history of every file in the KB. It never authorizes a retry.
    for values in execution_pages(job,deadline):
        selected=[v for v in values if v.get('file_id')==fid]
        if selected:
            value=selected[0]
            require(value.get('workflow_id')==KB_WORKFLOW_ID and value.get('dispatch_job_id')
                    and value.get('status') in EXECUTION_SUCCESS,'maintenance_execution_not_successful')
            return value
    raise ValueError('maintenance_execution_not_found')


def knowledge_probe(api,objects,date,run_id):
    pointer=read_json(objects,'daily/'+date.replace('-','')+'/ready.json',missing=True)
    if pointer is None:
        return dict(kb_contract_check_available=False,kb_contract_check_reason='no_current_ready',no_group_send=True)
    require(pointer.get('date')==date and pointer.get('scope')=='three-repositories',
            'maintenance_ready_identity_mismatch')
    prefix=pointer.get('prefix','')
    require(re.fullmatch('receipts/'+date.replace('-','')+'/pipeline-[A-Za-z0-9_-]{1,80}',prefix),
            'maintenance_ready_identity_mismatch')
    components=read_json(objects,prefix+'/components/checkpoint.json')
    require(components['date']==date and components['run_id']==pointer['run_id']
            and components['commits']==pointer['commits'],'maintenance_component_identity_mismatch')
    repo='taas';saved=components['repositories'][repo]
    require(saved.get('accepted'),'maintenance_component_not_accepted')
    artifacts=[saved['knowledge_index'],saved['artifacts']['employee']]
    targets=[dict(file_id=artifacts[0]['file_id'],marker=saved['marker']+'-DETAIL'),
             dict(file_id=artifacts[1]['file_id'],marker=saved['marker']+'-EMPLOYEE')]
    for item,target in zip(artifacts,targets):
        require(target['marker'].encode() in checked_file(api,item),'maintenance_marker_missing')
    check_prefix='receipts/'+date.replace('-','')+'/knowledge-contract-check-'+run_id
    journal=Journal(objects,check_prefix+'/checkpoint.json',dict(date=date,scope='knowledge-contract-check',
                    run_id=run_id,prefix=check_prefix,commits=pointer['commits']))
    job=Job(api,objects,journal,Path('out/knowledge-maintenance'))
    reads=[]
    for item in artifacts:
        start=time.monotonic();observed_file_execution(job,item['file_id'],time.time()+120)
        reads.append(round(time.monotonic()-start,3))
    ensure_sources(job,artifacts)
    proof=audit(job,targets,'maintenance_multifile')
    job.store('knowledge-proof.json',proof)
    return dict(kb_contract_check_available=True,kb_multifile_v3_verified=True,
                kb_observed_execution_verified=True,kb_execution_read_seconds=reads,
                original_daily_unchanged=True,no_group_send=True)
