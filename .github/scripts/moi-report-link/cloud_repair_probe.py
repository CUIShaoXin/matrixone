"""Cloud-only repair verification. Never send a message or enable a schedule."""
import datetime as dt
import json
import os
from pathlib import Path
import sys
import time
import uuid

import cloud_preflight as preflight
from cloud_daily import DailyAPI, Journal
from pipeline_telemetry import span,error_fields
from api_port_review import Job,REPOS,review_repository


def main():
    date=dt.datetime.now(preflight.LOCAL).date().isoformat()
    run_id=os.environ.get('MATRIX_REPAIR_RESUME') or os.environ['GITHUB_RUN_ID']+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
    mode=os.environ.get('MATRIX_REPAIR_MODE','archives')
    prefix='receipts/'+date.replace('-','')+'/repair-'+run_id
    out=Path('out/repair');out.mkdir(parents=True,exist_ok=True)
    status=dict(date=date,run_id=run_id,mode=mode,sent=False,daily_automation_ready=False,execution_head=os.environ.get('GITHUB_SHA'))
    start=time.monotonic()
    try:
        api=DailyAPI(os.environ['MOI_API_KEY']);objects=preflight.Objects.from_workspace(api)
        journal=Journal(objects,prefix+'/checkpoint.json',dict(date=date,scope='three-repositories',run_id=run_id,prefix=prefix,events=[],issues=[]))
        if mode=='archives':
            github=preflight.GitHub(os.environ['SCAN_GITHUB_TOKEN'])
            archives=journal.value.setdefault('archives',{})
            for repo in preflight.REPOSITORIES:
                if repo.name not in archives:
                    with span('fixed_archive_'+repo.name):
                        archives[repo.name]=preflight.prepare_archive(github,objects,repo,run_id,date);journal.save()
            status.update(status='passed',commits={k:v['commit'] for k,v in archives.items()},archives={k:dict(bytes=v['bytes'],sha256=v['sha256'],readback_verified=v['minio_readback_verified']) for k,v in archives.items()})
        else:
            # Explicit acquisition identity from this repair; never historical review contexts.
            source_run=os.environ['MATRIX_REPAIR_ARCHIVE_RUN']
            source=json.loads(objects.call('GET','receipts/'+date.replace('-','')+'/repair-'+source_run+'/checkpoint.json')[2])
            assert source['date']==date and source['scope']=='three-repositories'
            journal.value['commits']={k:v['commit'] for k,v in source['archives'].items()};journal.save()
            job=Job(api,objects,journal,out/'private')
            results={}
            # Shared Kimi semaphore also bounds calls across code/API stages in unified mode.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                pending={pool.submit(review_repository,job,r,source['archives'][r]):r for r in REPOS}
                for future in concurrent.futures.as_completed(pending):results[pending[future]]=future.result()
            job.store('accepted-api-results.json',results)
            status.update(status='passed',commits=journal.value['commits'],repositories={r:dict(findings=len(v['findings']),accepted=True) for r,v in results.items()})
    except Exception as exc:
        status.update(status='failed',**error_fields(exc))
        text=str(exc)
        if __import__('re').fullmatch('[a-z][a-z0-9_]{0,100}',text):status['safe_code']=text
    status['seconds']=round(time.monotonic()-start,3)
    (out/'status.json').write_text(json.dumps(status,indent=2));print(json.dumps(status),flush=True)
    return 0 if status['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
