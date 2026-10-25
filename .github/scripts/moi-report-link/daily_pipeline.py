"""Single cloud entry: fixed ZIP -> MOI OSV + Kimi code/API -> KB -> MinIO. No send."""
import concurrent.futures as futures
import datetime as dt
import json
import os
from pathlib import Path
import re
import time

import cloud_preflight as preflight
from cloud_daily import DailyAPI,Journal,Runner,require,json_bytes,WORKSPACE
from api_port_review import Job,REPOS,review_repository as api_review,publish_report,sha
from source_code_review import review_repository as code_review
from cloud_publish import verify_batch
from combined_renderer import render
from pipeline_telemetry import span,error_fields
from resilient_storage import verify_login_free


def verify_publication(api,objects,receipt_id,date,commits):
    receipt=json.loads(api.file(receipt_id))
    require(receipt['report_date']==date and receipt['commits']==commits and receipt.get('kb_marker_retrieved') and not receipt.get('sent'),'resumed_publication_identity_mismatch')
    require(dt.datetime.fromisoformat(receipt['expires_at_utc'])>dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=24),'resumed_publication_link_needs_renewal')
    for artifact in [dict(receipt['published'],url=receipt['url'])]+receipt['component_details']:
        stored=artifact.get('published',artifact)
        raw=objects.call('GET',stored['key'],response_limit=stored['bytes'])[2]
        require(len(raw)==stored['bytes'] and sha(raw)==stored['sha256'],'resumed_publication_hash_mismatch')
        verify_login_free(artifact['url'],raw)
    return receipt


def open_journal(objects,key,initial):
    journal=Journal(objects,key,initial)
    require(journal.value['run_id']==initial['run_id'],'resume_run_identity_mismatch')
    return journal


def main():
    date=dt.datetime.now(preflight.LOCAL).date().isoformat();start=time.monotonic()
    run_id=os.environ.get('MATRIX_PIPELINE_RESUME_RUN_ID') or os.environ['GITHUB_RUN_ID']+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
    mode=os.environ.get('MATRIX_PIPELINE_MODE','full')
    status=dict(schema='matrix_unified_no_send_status_v1',date=date,run_id=run_id,mode=mode,sent=False,daily_automation_ready=False,execution_head=os.environ.get('MATRIX_RUNTIME_SHA',os.environ.get('GITHUB_SHA')))
    out=Path('out/pipeline');out.mkdir(parents=True,exist_ok=True)
    try:
        require(re.fullmatch('[A-Za-z0-9_-]{1,80}',run_id) and mode in ('archives','reviews','full'),'invalid_pipeline_input')
        api=DailyAPI(os.environ['MOI_API_KEY']);objects=preflight.Objects.from_workspace(api)
        prefix='receipts/'+date.replace('-','')+'/pipeline-'+run_id
        root=open_journal(objects,prefix+'/checkpoint.json',dict(date=date,scope='three-repositories',run_id=run_id,prefix=prefix,sent=False))
        if root.value.get('published'):
            verify_publication(api,objects,root.value['publication_file_id'],date,root.value['commits'])
            status.update(status='passed',publication_file_id=root.value['publication_file_id'],same_batch_end_to_end_passed=True)
        else:
            archives=root.value.setdefault('archives',{})
            github=preflight.GitHub(os.environ.get('SCAN_GITHUB_TOKEN',''))
            require(bool(github.token),'missing_scan_github_token')
            with span('three_repository_acquisition'):
                for repo in preflight.REPOSITORIES:
                    if repo.name not in archives:
                        archives[repo.name]=preflight.prepare_archive(github,objects,repo,run_id,date);root.save()
                    proof=archives[repo.name]
                    require(proof['report_date']==date and proof['repository']=='matrixorigin/'+repo.name and proof['daily_cloud_download_verified'] and proof['minio_readback_verified'],'pipeline_archive_identity_mismatch')
            commits={r:p['commit'] for r,p in archives.items()};status['commits']=commits
            if mode=='archives':status.update(status='passed',same_batch_end_to_end_passed=False,archives_verified=True)
            else:
                review_journal=open_journal(objects,prefix+'/reviews/checkpoint.json',dict(date=date,scope='three-repositories',run_id=run_id,prefix=prefix+'/reviews',commits=commits,issues=[],events=[],unified_current_batch=True,source_id=None,source_sha256=None))
                require(review_journal.value['commits']==commits,'review_resume_commit_mismatch')
                job=Job(api,objects,review_journal,out/'private')
                code={};api_results={}
                def all_reviews():
                    with futures.ThreadPoolExecutor(max_workers=2) as pool:
                        pending={pool.submit(function,job,r,archives[r]):(kind,r) for kind,function in [('code',code_review),('api',api_review)] for r in REPOS}
                        failures=[]
                        for future in futures.as_completed(pending):
                            kind,r=pending[future]
                            try:(code if kind=='code' else api_results)[r]=future.result()
                            except Exception as exc:
                                error=str(exc) if re.fullmatch('[a-z][a-z0-9_]{0,100}',str(exc)) else type(exc).__name__
                                failures.append((kind,r,error));job.issue(kind+'_'+r,error,'Keep exact task and checkpoint; publication remains blocked')
                        if failures:raise ValueError('source_review_incomplete')
                with futures.ThreadPoolExecutor(max_workers=1) as model_pool:
                    model_future=model_pool.submit(all_reviews)
                    if mode=='full':
                        component_journal=open_journal(objects,prefix+'/components/checkpoint.json',dict(date=date,scope='three-repositories',run_id=run_id,prefix=prefix+'/components',archives=archives,commits=commits,sent=False))
                        require(component_journal.value['archives']==archives,'component_resume_archive_mismatch')
                        runner=Runner(api,objects,component_journal)
                        try:
                            with span('three_repository_component_scan'):
                                results={repo.name:runner.scan(repo,archives[repo.name]) for repo in preflight.REPOSITORIES}
                        except Exception as exc:
                            failure=dict(stage='components',**error_fields(exc),at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
                            if re.fullmatch('[a-z][a-z0-9_]{0,100}',str(exc)):failure['safe_code']=str(exc)
                            root.value.setdefault('failures',[]).append(failure);root.save()
                            raise
                        batch=dict(schema='matrix_daily_acceptance_v1',date=date,workspace=WORKSPACE,knowledge_base_id=80001,results=results,three_repository_reports_accepted=True,single_repository_test=False,daily_cloud_download_verified=True,sent=False,daily_automation_ready=False)
                    model_future.result()
                if mode=='reviews':
                    status.update(status='passed',same_batch_end_to_end_passed=False,code_repositories=list(code),api_repositories=list(api_results))
                else:
                    files={(r,k):api.file(v['artifacts'][k]['file_id']) for r,v in results.items() for k in ('employee','details','osv')}
                    verify_batch(batch,files,date)
                    job.component_osv={r:json.loads(files[(r,'osv')]) for r in REPOS}
                    page,ncomp,ncode=render(batch,files,code)
                    source=dict(schema='matrix_unified_scan_source_v1',report_date=date,scope='three-repositories',run_id=run_id,commits=commits,source_acceptance=batch,code_review=dict(model='kimi-k3',repositories=code),component_focus_count=ncomp,code_findings=ncode,kb_marker_retrieved=True,sent=False)
                    body=json_bytes(source);job.store('same-batch-source.json',body)
                    artifact=review_journal.value.get('source_artifact')
                    if artifact:require(api.file(artifact['file_id'])==body,'pipeline_source_artifact_mismatch')
                    else:
                        artifact=api.upload('matrix-same-batch-source-'+run_id+'.json',body);review_journal.value['source_artifact']=artifact
                    review_journal.value.update(source_id=artifact['file_id'],source_sha256=sha(body));review_journal.save()
                    if review_journal.value.get('published'):
                        saved=review_journal.value['receipt'];receipt=verify_publication(api,objects,saved['file_id'],date,commits);receipt['receipt_artifact']=saved
                    else:receipt=publish_report(job,source,page,api_results)
                    root.value.update(published=True,publication_file_id=receipt['receipt_artifact']['file_id'],commits=commits);root.save()
                    status.update(status='passed',same_batch_end_to_end_passed=True,publication_file_id=root.value['publication_file_id'],component_focus_count=ncomp,code_findings=ncode,api_port_findings=receipt['added_findings'],kb_verified=True,minio_login_free_verified=True)
    except Exception as exc:
        status.update(status='failed',same_batch_end_to_end_passed=False,**error_fields(exc))
        if re.fullmatch('[a-z][a-z0-9_]{0,100}',str(exc)):status['safe_code']=str(exc)
    status.update(seconds=round(time.monotonic()-start,3),finished_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    (out/'status.json').write_bytes(json_bytes(status));print(json.dumps(status),flush=True)
    return 0 if status['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
