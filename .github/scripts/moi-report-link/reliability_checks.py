"""No-send maintenance checks against the day's already accepted KB files."""
from pathlib import Path
import re
import time

from cloud_daily import Journal,require
from daily_delivery import read_json,checked_file
from api_port_review import Job
from knowledge_gate import audit,ensure_sources,execution_facts,EXECUTION_SUCCESS


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
        start=time.monotonic();facts=execution_facts(job,item['file_id'],time.time()+120)
        require(any(v.get('status') in EXECUTION_SUCCESS for v in facts),'maintenance_execution_not_successful')
        reads.append(round(time.monotonic()-start,3))
    ensure_sources(job,artifacts)
    proof=audit(job,targets,'maintenance_multifile')
    job.store('knowledge-proof.json',proof)
    return dict(kb_contract_check_available=True,kb_multifile_v3_verified=True,
                kb_execution_facts_verified=True,kb_fact_read_seconds=reads,
                original_daily_unchanged=True,no_group_send=True)
