"""Recoverable named MOI uploads with durable intent and exact-byte reconciliation."""
import datetime as dt
import hashlib
import json
import uuid

from resilient_storage import SignedObjects


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_json(objects, key):
    try:
        return json.loads(objects.call('GET', key)[2])
    except RuntimeError as exc:
        if str(exc) == 'minio_http_404':
            return None
        raise


def create_once(objects, key, value):
    raw = json_bytes(value)
    try:
        SignedObjects.call(objects, 'PUT', key, raw, {
            'if-none-match': '*', 'content-type': 'application/json',
            'x-amz-meta-sha256': sha(raw),
        })
        require(objects.call('GET', key)[2] == raw, 'native_upload_intent_readback_mismatch')
        return True, value
    except RuntimeError as exc:
        if str(exc) != 'minio_http_412':
            raise
        return False, read_json(objects, key)


def checked_file(api, artifact):
    raw = api.file(artifact['file_id'])
    require(len(raw) == artifact['bytes'] and sha(raw) == artifact['sha256'],
            'native_upload_readback_mismatch')
    return raw


def exact_file(api, name, raw, volume_id=130001):
    answer = api.data(api.request('/catalog/file/list', {
        'filters': [dict(name='volume_id', values=[str(volume_id)]),
                    dict(name='file_name', values=[name])],
        'page': 1, 'page_size': 100}, timeout=90))
    rows = [item for item in answer.get('list', [])
            if item.get('name') == name and str(item.get('volume_id')) == str(volume_id)]
    require(answer.get('total') == len(answer.get('list', [])), 'native_upload_inventory_incomplete')
    require(len(rows) <= 1, 'native_upload_name_ambiguous')
    if not rows:
        return None
    fid = rows[0].get('file_id', rows[0].get('id'))
    artifact = dict(file_id=fid, bytes=len(raw), sha256=sha(raw),
                    readback_verified=True, name=name)
    require(api.file(fid) == raw, 'native_upload_existing_bytes_mismatch')
    return artifact


def upload_named_once(api, objects, intent_key, name, raw, volume_id=130001):
    """Upload at most once; after uncertainty only the original file may be recovered."""
    pointer_key = intent_key + '-artifact.json'
    saved = read_json(objects, pointer_key)
    if saved is not None:
        require(saved.get('name') == name and checked_file(api, saved) == raw,
                'native_upload_pointer_mismatch')
        return saved
    found = exact_file(api, name, raw, volume_id)
    if found is not None:
        _, persisted = create_once(objects, pointer_key, found)
        require(persisted == found, 'native_upload_pointer_conflict')
        return persisted

    intent = read_json(objects, intent_key)
    if intent is None:
        _, intent = create_once(objects, intent_key, dict(
            schema='matrix_named_upload_intent_v1', name=name, bytes=len(raw),
            sha256=sha(raw), volume_id=volume_id, submission_attempted=False,
            owner=str(uuid.uuid4())))
    require(intent.get('name') == name and intent.get('bytes') == len(raw)
            and intent.get('sha256') == sha(raw) and intent.get('volume_id') == volume_id,
            'native_upload_intent_conflict')
    require(intent.get('submission_attempted') is not True, 'native_upload_submission_unknown')
    intent = dict(intent, submission_attempted=True,
                  attempted_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    objects.publish(intent_key, json_bytes(intent), 'application/json')
    try:
        uploaded = api.upload(name, raw)
    except Exception as original:
        recovered = exact_file(api, name, raw, volume_id)
        if recovered is None:
            raise ValueError('native_upload_submission_unknown') from original
        uploaded = recovered
    artifact = dict(file_id=uploaded['file_id'], bytes=len(raw), sha256=sha(raw),
                    readback_verified=True, name=name)
    require(checked_file(api, artifact) == raw, 'native_upload_readback_mismatch')
    _, persisted = create_once(objects, pointer_key, artifact)
    require(persisted == artifact, 'native_upload_pointer_conflict')
    return persisted
