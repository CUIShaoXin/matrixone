"""Durable fixed-commit acquisition journal; no source is executed."""
import datetime as dt
import json
from pathlib import Path
import re
import tempfile
from pipeline_telemetry import span, emit
from resilient_storage import sha256


def prepare(github, objects, repository, run_id, date, validate, failure):
    full_name = repository.owner+'/'+repository.name
    journal_key = 'receipts/'+date.replace('-','')+'/acquisition-'+run_id+'/'+repository.name+'.json'
    try:
        state = json.loads(objects.call('GET',journal_key)[2])
        if (state['repository'],state['date'],state['run_id'],state['branch']) != (full_name,date,run_id,repository.branch):
            raise failure('acquisition_identity_mismatch')
    except RuntimeError as exc:
        if str(exc) != 'minio_http_404': raise
        commit = github.get(full_name,'/branches/'+repository.branch)['commit']['sha']
        if not re.fullmatch('[0-9a-f]{40}',commit): raise failure('github_commit_invalid')
        state = dict(repository=full_name,branch=repository.branch,date=date,run_id=run_id,commit=commit,transfer={})
    def save():
        objects.publish(journal_key,json.dumps(state,ensure_ascii=False).encode(),'application/json')
    save()  # Commit is durable before download or upload.
    commit = state['commit']
    key = 'snapshots/'+date.replace('-','')+'/'+repository.name+'/'+repository.name+'-'+commit+'-gha-'+run_id+'.zip'
    if state.get('key',key) != key: raise failure('acquisition_key_mismatch')
    proof = state.get('proof')
    if proof and objects.verify_object(key,proof['bytes'],proof['sha256']):
        raw = None
    else:
        cache = Path(tempfile.gettempdir())/'matrix-archive-cache'/(repository.owner+'-'+repository.name+'-'+commit)
        cache.parent.mkdir(parents=True,exist_ok=True)
        raw = cache.read_bytes() if cache.exists() else None
        if raw is not None and proof and sha256(raw)!=proof['sha256']:
            raise failure('archive_cache_hash_mismatch')
        if raw is None:
            with span('github_fixed_archive_download', repository=repository.name, commit=commit):
                raw = github.get(full_name,'/zipball/'+commit,binary=True)
            cache.write_bytes(raw); cache.chmod(0o600)
        with span('archive_validation', repository=repository.name, commit=commit, bytes=len(raw)):
            with tempfile.TemporaryFile() as stream:
                stream.write(raw); current = validate(stream,commit)
        if proof and (current['sha256'],current['bytes']) != (proof['sha256'],proof['bytes']):
            raise failure('fixed_archive_bytes_changed')
        proof = current
        state.update(key=key,proof=proof);save()  # Size/hash precede any PUT.
        objects.put_verified(key,raw,proof['sha256'],state['transfer'],save)
        cache.unlink(missing_ok=True)
    proof.update(repository=full_name,branch=repository.branch,key=key,report_date=date,
        acquisition_location='GitHub Actions cloud runner',download_method='fixed-commit GitHub repository archive API',
        daily_cloud_download_verified=True,minio_readback_verified=True,repository_code_executed=False,
        private_dependency_source_downloaded=False,acquired_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    state.update(proof=proof,status='verified');save()
    objects.publish(key[:-4]+'-inventory.json',json.dumps(proof,ensure_ascii=False,indent=2).encode(),'application/json')
    emit('archive_accepted',repository=repository.name,commit=commit,bytes=proof['bytes'])
    return proof
