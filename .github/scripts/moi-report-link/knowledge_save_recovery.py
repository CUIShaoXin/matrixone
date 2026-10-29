"""One reserved official node continuation for the proven KB catalog HTTP 500.

Unknown POST acknowledgements are observed, never resubmitted. No overrides,
file upload, reindex, new workflow, or change to the original ingestion clock.
"""
import hashlib
import json
import re
import time

NODE='root.save_output'


def sink_failure(error):
    return re.fullmatch(r'\[moi:catalog\.sink\.write\] \[1\] Internal Server Error '
                        r'\(request_id: [0-9a-f-]{36}\)',error or '') is not None


def reservation_digest(job,fid,eid,request):
    value=dict(prefix=job.state['prefix'],file_id=fid,execution_id=eid,node=NODE,request=request)
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def recover_save_node(job,fid,state,latest=None,deadline=None):
    from knowledge_gate import (KB_WORKFLOW_ID,WORKFLOWS,execution_dispatch,
                                fact_timeout,transient)
    from pipeline_telemetry import emit
    recovery=state.get('save_node_recovery')

    def read(path):
        return job.api.data(job.api.request(path,timeout=min(15,fact_timeout(deadline)),retry=False))

    def execution(path,eid):
        value=read(path).get('execution',{})
        if (value.get('execution_id')!=eid or value.get('workflow_id')!=KB_WORKFLOW_ID
                or value.get('input_payload',{}).get('file_id')!=fid):
            raise ValueError('knowledge_save_execution_identity_mismatch')
        return value

    def validate_branch(value):
        request=recovery['request']
        if (value.get('source_execution_id')!=recovery['original_execution']['execution_id']
                or value.get('source_node_execution_id')!=request['source_node_execution_id']
                or value.get('node_key')!=NODE or value.get('mode')!='rerun_current_and_downstream'
                or not value.get('rerun_id') or not value.get('branch_id') or not value.get('case_id')
                or not value.get('new_workflow_execution_id')
                or value['new_workflow_execution_id']==recovery['original_execution']['execution_id']
                or value.get('source_case_id')!=recovery['plan']['source_case_id']
                or value.get('source_branch_id')!=recovery['plan']['source_branch_id']):
            raise ValueError('knowledge_save_rerun_identity_mismatch')
        if recovery.get('rerun'):
            for key in ('rerun_id','branch_id','case_id','new_workflow_execution_id'):
                if value[key]!=recovery['rerun'][key]:
                    raise ValueError('knowledge_save_rerun_identity_mismatch')
        return value

    if recovery:
        original=recovery['original_execution'];eid=original['execution_id']
        if (recovery.get('attempts')!=1 or recovery.get('file_id')!=fid
                or original.get('workflow_id')!=KB_WORKFLOW_ID
                or recovery.get('reservation_sha256')!=reservation_digest(job,fid,eid,recovery['request'])):
            raise ValueError('knowledge_save_checkpoint_identity_mismatch')
        if recovery['status']=='blocked':raise ValueError('knowledge_save_recovery_blocked')
        if recovery['status'] not in ('accepted','submission_unknown'):
            raise ValueError('knowledge_save_checkpoint_identity_mismatch')
        route=WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions/'+eid
        values=read(route+'/rerun-branches').get('reruns')
        if not isinstance(values,list) or len(values)>1:
            raise ValueError('knowledge_save_rerun_ambiguous')
        if not values:return True
        branch=validate_branch(values[0])
        branch=validate_branch(read(route+'/reruns/'+branch['rerun_id']).get('rerun',{}))
        recovery['rerun']=branch
        if branch.get('status') in ('failed','cancelled'):
            recovery['status']='blocked';job.journal.save()
            raise ValueError('knowledge_save_recovery_exhausted')
        if branch.get('status')=='succeeded':
            new=execution(WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions/'+branch['new_workflow_execution_id'],branch['new_workflow_execution_id'])
            if new.get('input_payload')!=recovery['original_input']:
                raise ValueError('knowledge_save_rerun_input_changed')
            if new.get('status') not in ('completed','success','succeeded'):
                raise ValueError('knowledge_save_rerun_status_mismatch')
            recovery['new_execution']=new
        elif branch.get('status') not in ('ready','running','pending','preparing','waiting','submitted','queued'):
            raise ValueError('knowledge_save_rerun_status_unknown')
        job.journal.save()
        return True

    if not latest or latest.get('status')!='failed' or not sink_failure(latest.get('error')):
        raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
    eid=latest['execution_id'];route=WORKFLOWS+'/'+KB_WORKFLOW_ID+'/executions/'+eid
    original=execution_dispatch(job,fid,eid,deadline)
    if (original.get('status')!='failed' or original.get('error')!=latest.get('error')
            or latest.get('execution_mode')!='volume_trigger'):
        raise ValueError('knowledge_save_execution_identity_mismatch')
    detail=execution(route,eid)
    if detail.get('status')!='failed' or detail.get('error')!=latest['error']:
        raise ValueError('knowledge_save_execution_identity_mismatch')
    plan=read(route+'/nodes/'+NODE+'/rerun-plan').get('plan',{})
    candidates=plan.get('candidates',[])
    if (plan.get('workflow_id')!=KB_WORKFLOW_ID or plan.get('source_execution_id')!=eid
            or plan.get('node_key')!=NODE or plan.get('node_status')!='FAILED'
            or plan.get('validation',{}).get('ok') is not True
            or 'continue_from_node' not in plan.get('available_modes',[])
            or plan.get('affected_downstream_nodes')!=[dict(node_key='root.register_lineage',node_type='data.lineage.register')]
            or not plan.get('source_case_id') or not plan.get('source_branch_id')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',plan.get('rerun_contract_hash',''))
            or len(candidates)!=1 or candidates[0].get('source_node_execution_id')!=plan.get('source_node_execution_id')
            or not plan.get('source_node_execution_id') or candidates[0].get('status')!='FAILED'
            or candidates[0].get('error')!=latest['error']):
        raise ValueError('knowledge_save_plan_not_safe')
    if read(route+'/rerun-branches').get('reruns')!=[]:
        raise ValueError('knowledge_save_prior_rerun_exists')
    request=dict(mode='continue_from_node',source_node_execution_id=plan['source_node_execution_id'],
                 expected_rerun_contract_hash=plan['rerun_contract_hash'],
                 reason='Recover original daily KB file catalog sink HTTP 500; preserve completed upstream and original input; no overrides.')
    recovery=dict(attempts=1,file_id=fid,original_execution=dict(latest),original_dispatch=original,
                  original_input=detail['input_payload'],plan=plan,request=request,status='submission_unknown',reserved_epoch=time.time(),
                  reservation_sha256=reservation_digest(job,fid,eid,request))
    state['save_node_recovery']=recovery
    try:job.journal.save()
    except Exception:raise ValueError('knowledge_save_checkpoint_unconfirmed') from None
    timeout=fact_timeout(deadline)  # Recheck after durable reservation, before POST.
    try:
        answer=job.api.data(job.api.request(route+'/nodes/'+NODE+'/reruns',request,method='POST',timeout=timeout))
    except Exception as exc:
        if transient(exc):
            emit('knowledge_save_submission_unknown',same_sources=True,attempts=1)
            return True
        recovery['status']='blocked';job.journal.save()
        raise ValueError('knowledge_save_recovery_rejected') from None
    try:branch=validate_branch(answer.get('rerun',{}))
    except Exception:
        recovery['status']='blocked';job.journal.save();raise
    recovery.update(status='accepted',rerun=branch);job.journal.save()
    emit('knowledge_save_node_recovery_accepted',same_sources=True,attempts=1)
    return True
