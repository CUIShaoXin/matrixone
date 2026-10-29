"""Same-day verified delivery, with a non-expiring atomic claim per day/group.

An uncertain send is never submitted again. Recovery only reads the original
runtime task. The claim deliberately favors a missed delivery over a duplicate.
"""
import copy
import datetime as dt
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import time
import uuid
import urllib.error

from cloud_daily import DailyAPI, WORKSPACE, json_bytes, verify_rag
from cloud_publish import verify_batch
from resilient_storage import Objects, SignedObjects, verify_login_free
from api_port_review import llm_calls
from pipeline_telemetry import span, error_fields

LOCAL = dt.timezone(dt.timedelta(hours=8))
REPOS = ('matrixone', 'taas', 'matrixflow')
NAMES = dict(zip(REPOS, ('MatrixOne', 'TaaS', 'MatrixFlow')))
CHANNEL = '09567f53-8dad-41d8-842e-2e269a6c86e2'
_DAILY_API_TYPE = DailyAPI
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_json(objects, key, missing=False):
    try:
        return json.loads(objects.call('GET', key)[2])
    except RuntimeError as exc:
        if missing and str(exc) == 'minio_http_404':
            return None
        raise


def create_once(objects, key, value):
    """One conditional PUT. Do not route through retrying publish/PUT helpers."""
    raw = json_bytes(value)
    try:
        put = objects.call if isinstance(objects, RecoveryObjects) else lambda *args: SignedObjects.call(objects, *args)
        put('PUT', key, raw, {
            'if-none-match': '*', 'content-type': 'application/json',
            'x-amz-meta-sha256': sha(raw),
        })
        require(objects.call('GET', key)[2] == raw, 'atomic_claim_readback_mismatch')
        return True, value
    except RuntimeError as exc:
        if str(exc) != 'minio_http_412':
            raise
        return False, read_json(objects, key)


def checked_file(api, artifact):
    raw = api.file(artifact['file_id'])
    require(len(raw) == artifact['bytes'] and sha(raw) == artifact['sha256'], 'delivery_file_hash_mismatch')
    return raw


def final_kb_task(tasks,commits):
    repo=sorted(commits)[0]
    values=[v for k,v in tasks.items() if k in
            (repo+'_kb_final_report_scope_v2',repo+'_kb_final_report_scope_v3')]
    require(len(values)==1 and values[0].get('task_id'),'delivery_final_kb_task_missing')
    return values[0]


def check_bundle(api, objects, prefix, date):
    """Re-read accepted immutable inputs and actual final KB task, no inference."""
    require(re.fullmatch(r'receipts/' + date.replace('-', '') + r'/pipeline-[A-Za-z0-9_-]{1,80}', prefix), 'delivery_batch_prefix_invalid')
    root = read_json(objects, prefix + '/checkpoint.json')
    reviews = read_json(objects, prefix + '/reviews/checkpoint.json')
    require(root['date'] == reviews['date'] == date and root['scope'] == reviews['scope'] == 'three-repositories', 'delivery_wrong_date_or_scope')
    require(root.get('published') and reviews.get('published') and reviews.get('unified_current_batch'), 'delivery_batch_not_published')
    require(set(root['archives']) == set(REPOS) and set(root['commits']) == set(REPOS), 'delivery_repository_missing')
    for repo in REPOS:
        a = root['archives'][repo]
        require(a['report_date'] == date and a['repository'] == 'matrixorigin/' + repo and a['commit'] == root['commits'][repo] and a.get('daily_cloud_download_verified') and a.get('minio_readback_verified'), 'delivery_archive_not_verified')
    receipt_raw = api.file(root['publication_file_id'])
    r = json.loads(receipt_raw)
    require(r['report_date'] == date and r['run_id'] == root['run_id'] and r['commits'] == root['commits'] and r['scope'] == 'three-repositories', 'delivery_publication_identity_mismatch')
    require(r.get('kb_marker_retrieved') and r.get('rg_cloud_execution') and r.get('model') == 'kimi-k3' and not r.get('publication_only_revision'), 'delivery_publication_evidence_missing')
    require(dt.datetime.fromisoformat(r['expires_at_utc']) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24), 'delivery_links_expire_too_soon')
    source_raw = api.file(r['source_receipt_file_id'])
    require(sha(source_raw) == r['source_receipt_sha256'], 'delivery_source_hash_mismatch')
    source = json.loads(source_raw)
    require(source['report_date'] == date and source['run_id'] == root['run_id'] and source['commits'] == root['commits'] and source['scope'] == 'three-repositories', 'delivery_source_identity_mismatch')
    batch = source['source_acceptance']
    files = {(repo, kind): checked_file(api, v['artifacts'][kind]) for repo, v in batch['results'].items() for kind in ('osv', 'employee', 'details')}
    verify_batch(batch, files, date)
    accepted = read_json(objects, prefix + '/reviews/acceptance.json')
    require(not accepted.get('component_batch_reused') and not accepted.get('code_batch_reused') and accepted['source_commits'] == root['commits'], 'delivery_mixed_batch')
    api_results = accepted['repositories']
    codes = source['code_review']['repositories']
    require(set(api_results) == set(codes) == set(REPOS), 'delivery_review_repository_missing')
    for repo in REPOS:
        for kind, value in [('code', codes[repo]), ('api', api_results[repo])]:
            saved = reviews['code_repositories' if kind == 'code' else 'repositories'][repo]
            require(saved.get('accepted'), 'delivery_source_review_not_accepted')
            artifact = saved['result']
            raw = objects.call('GET', artifact['key'])[2]
            require(len(raw) == artifact['bytes'] and sha(raw) == artifact['sha256'] and json.loads(raw) == value, 'delivery_review_artifact_mismatch')
            require(value['commit'] == root['commits'][repo] and value['archive_proof']['report_date'] == date and not value.get('whole_repository_review'), 'delivery_review_identity_mismatch')
            proof = value['actual_model_execution_proof']
            require(all(proof.get(k) and all(m.get('model') == 'kimi-k3' and m.get('status') == 'completed' for m in proof[k]) for k in ('primary', 'final')), 'delivery_actual_review_model_missing')
    marker = 'MATRIX-API-PORT-' + date.replace('-', '') + '-' + root['run_id']
    kb = final_kb_task(reviews['model_tasks'],root['commits'])
    task = api.rpc('tasks/get', {'id': kb['task_id']}, str(uuid.uuid4()))
    verify_rag(task, [dict(file_id=r['markdown_artifact']['file_id'], marker=marker)])
    require(task.get('status', {}).get('state') == 'completed' and llm_calls(task) and all(m.get('model') == 'kimi-k3' and m.get('status') == 'completed' for m in llm_calls(task)), 'delivery_kb_task_not_completed')
    md = checked_file(api, r['markdown_artifact'])
    require(marker.encode() in md, 'delivery_native_marker_missing')
    pages = [dict(published=r['published'], url=r['url'], expires_at_utc=r['expires_at_utc'])] + r['component_details']
    require(len(r['component_details']) == len(source['component_focus']) > 0, 'delivery_component_detail_missing')
    main = None
    for p in pages:
        artifact = p['published']
        require(p['expires_at_utc'] == r['expires_at_utc'], 'delivery_detail_expiry_mismatch')
        raw = objects.call('GET', artifact['key'], response_limit=artifact['bytes'])[2]
        require(len(raw) == artifact['bytes'] and sha(raw) == artifact['sha256'], 'delivery_page_hash_mismatch')
        verify_login_free(p['url'], raw)
        if main is None:
            main = raw
        else:
            require(p['url'].replace('&', '&amp;').encode() in main and p['commit'] == root['commits'][p['repository']], 'delivery_detail_link_mismatch')
    require(all(('id="' + s + '"').encode() in main for s in ('components', 'code', 'api-port')), 'delivery_report_sections_missing')
    return dict(root=root, receipt=r, source=source, api_results=api_results,
                publication_sha256=sha(receipt_raw), pages_verified=len(pages))


def export_ready(api, objects, prefix, date):
    with span('daily_delivery_readiness'):
        bundle = check_bundle(api, objects, prefix, date)
        pointer = dict(schema='matrix_daily_ready_v1', date=date, scope='three-repositories',
                       prefix=prefix, run_id=bundle['root']['run_id'], commits=bundle['root']['commits'],
                       publication_file_id=bundle['root']['publication_file_id'],
                       publication_sha256=bundle['publication_sha256'],
                       verified_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        _, saved = create_once(objects, 'daily/' + date.replace('-', '') + '/ready.json', pointer)
        require(all(saved.get(k) == pointer[k] for k in ('schema', 'date', 'scope', 'prefix', 'run_id', 'commits', 'publication_file_id', 'publication_sha256')), 'daily_ready_conflict')
        return pointer


def brief(text, limit=42):
    text = re.sub(r'\s+', ' ', str(text)).strip()
    text = text[:limit] + ('…' if len(text) > limit else '')
    return re.sub(r'([\\`*_{}\[\]()<>])', r'\\\1', text)


def compose(bundle, date):
    source, r = bundle['source'], bundle['receipt']
    lines = ['【安全日报｜组件＋代码＋API／端口】', date, '']
    for repo in REPOS:
        components = [c for c in source['component_focus'] if c['repo'] == repo]
        code = source['code_review']['repositories'][repo]['retained_findings']
        apis = bundle['api_results'][repo]['findings']
        lines += ['**' + NAMES[repo] + '**']
        lines += ['• 组件：' + ('；'.join(brief(c['label'], 18) + '：' + brief(c['risk'], 32) for c in components) or '本期未列重点项')]
        lines += ['• 代码：' + ('；'.join(brief(f['title']) for f in code) or '本轮所审模块未保留充分线索')]
        lines += ['• API／端口：' + ('；'.join(brief(f['title']) for f in apis) or '本轮所审上下文未保留充分线索'), '']
    lines += ['[查看完整日报（免登录）](' + r['url'] + ')',
              '点击组件名称可看详情。链接至 ' + dt.datetime.fromisoformat(r['expires_at_utc']).astimezone(LOCAL).strftime('%m-%d %H:%M') + '。',
              '均需研发核实触发条件；源码审查覆盖选定上下文，端口实际暴露尚未探测。']
    content = '\n'.join(lines)
    require(len(content.encode()) <= 4096, 'delivery_message_exceeds_limit')
    return content


def prior_delivery(api, date):
    """Inspect older native delivery receipts as well as the new global claim."""
    for page in range(1, 101):
        result = api.data(api.request('/catalog/file/list', {'filters': [{'name': 'volume_id', 'values': ['130001']}], 'page': page, 'page_size': 100}))
        rows = result.get('list')
        require(isinstance(rows, list), 'delivery_history_unreadable')
        for row in rows:
            name = row.get('origin_file_name') or row.get('name', '')
            if 'delivery' in name and date.replace('-', '') in name and name.endswith('.json'):
                value = json.loads(api.file(row.get('file_id', row.get('id'))))
                if value.get('channel_instance_id') == CHANNEL and (value.get('sent') or value.get('status') in ('sending', 'uncertain', 'sent')):
                    raise ValueError('native_prior_delivery_requires_reconciliation')
        if len(rows) < 100:
            return
    raise ValueError('delivery_history_pagination_incomplete')


def send_events(task, kind):
    found = {}
    def walk(v):
        if isinstance(v, dict):
            if v.get('type') == kind and 'wecom_robot_message' in v.get('toolId', ''):
                cid = v['callId']
                require(cid not in found or found[cid] == v, 'delivery_invocation_count_invalid')
                found[cid] = v
            for c in v.values(): walk(c)
        elif isinstance(v, list):
            for c in v: walk(c)
    walk(task)
    return found


def verify_send(task, claim):
    require(task.get('id') == claim['task_id'] and task.get('status', {}).get('state') == 'completed', 'delivery_task_incomplete')
    calls, results = send_events(task, 'moi.tool.call'), send_events(task, 'moi.tool.result')
    require(len(calls) == len(results) == 1 and calls.keys() == results.keys(), 'delivery_invocation_count_invalid')
    cid = next(iter(calls))
    args = calls[cid]['arguments']
    require(args.get('channel_instance_id') == CHANNEL and args.get('msg_type') == 'markdown' and args.get('content') == claim['content'], 'delivery_sent_content_mismatch')
    result = results[cid]['output']
    require(isinstance(result, dict), 'delivery_tool_output_invalid')
    output = result.get('output', result)
    require(isinstance(output, dict), 'delivery_tool_output_invalid')
    legacy = output.get('ok') is True and output.get('status') == 'COMPLETED' and output.get('data', {}).get('ok') is True and output.get('request_id') == cid
    # Current native channel runtime returns a typed acknowledgement instead
    # of the former work-item envelope. Bind every identity; a model's "sent"
    # text or an arbitrary {ok:true} cannot satisfy either supported protocol.
    native = (result.get('call_id') == cid and result.get('tool_id') == 'moi_wecom_robot_message'
              and isinstance(result.get('created_at'), str) and output.get('ok') is True
              and output.get('operation') == 'group_robot_send' and output.get('request_id') == cid
              and output.get('workspace_id') == WORKSPACE)
    require(legacy or native, 'delivery_real_tool_receipt_missing')
    if native:
        # Go emits nanoseconds; Python 3.9 accepts at most microseconds.
        stamp = re.sub(r'(\.\d{6})\d+', r'\1', result['created_at']).replace('Z', '+00:00')
        at = dt.datetime.fromisoformat(stamp)
        require(at.tzinfo is not None and at.astimezone(LOCAL).date().isoformat() == claim['date'], 'delivery_ack_wrong_date')
    final = dict(schema='matrix_daily_delivery_v1', date=claim['date'], scope='three-repositories',
                sent=True, status='sent', channel_instance_id=CHANNEL, task_id=task['id'],
                attempt_id=claim['attempt_id'], tool_call_id=cid, tool_output=result,
                tool_receipt_protocol='native_channel_ack_v1' if native else 'work_item_completed_v1',
                sent_at_utc=result.get('created_at'),
                content=claim['content'], content_sha256=sha(claim['content'].encode()),
                publication_file_id=claim['publication_file_id'], prefix=claim['prefix'],
                verified_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    if 'report_identity' in claim:
        final['report_identity'] = claim['report_identity']
    return final


# The same budget covers polling and receipt reconciliation. A zero poll interval
# is useful for fault drills; the attempt cap also prevents a hot retry loop.
MAX_RECOVERY_ATTEMPTS = 128
REPORT_IDENTITY_FIELDS = ('schema', 'date', 'scope', 'prefix', 'run_id', 'commits',
                          'publication_file_id', 'publication_sha256')


def transient(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (408, 429, 500, 502, 503, 504)
    return (isinstance(exc, (TimeoutError, ConnectionError, urllib.error.URLError,
                             http.client.IncompleteRead))
            or str(exc) in tuple(prefix + str(c) for prefix in ('minio_http_', 'moi_http_')
                                 for c in (408, 429, 500, 502, 503, 504)))


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ValueError('delivery_uncertain_read_original_task_only')
    return left


def pause(deadline, poll_seconds):
    time.sleep(min(max(poll_seconds, 0), remaining(deadline)))


class DeadlineOpener:
    def __init__(self, opener, deadline):
        self.opener, self.deadline = opener, deadline

    def open(self, request, timeout=60):
        return self.opener.open(request, timeout=min(timeout, remaining(self.deadline)))


class RecoveryAPI:
    """Keep the client's per-request socket timeout within the shared budget."""
    def __init__(self, api, deadline):
        if isinstance(api, _DAILY_API_TYPE):
            api = copy.copy(api)
            api.opener = DeadlineOpener(api.opener, deadline)
            # Recovery owns retries; avoid nested client loops and sleeps.
            api.file = super(_DAILY_API_TYPE, api).file
            api.request = super(_DAILY_API_TYPE, api).request
        self.api, self.deadline = api, deadline

    def __getattr__(self, name):
        method = getattr(self.api, name)
        def call(*args, **kwargs):
            remaining(self.deadline)
            result = method(*args, **kwargs)
            remaining(self.deadline)
            return result
        return call


class RecoveryObjects:
    """One storage operation per attempt; bypass Objects' nested retry budgets."""
    def __init__(self, objects, deadline):
        self.objects, self.deadline = objects, deadline

    def call(self, method, key, raw=None, headers=None):
        timeout = min(45, remaining(self.deadline))
        if isinstance(self.objects, SignedObjects):
            return SignedObjects.call(self.objects, method, key, raw, headers, timeout=timeout)
        return self.objects.call(method, key, raw, headers, timeout=timeout)

    def publish(self, key, raw, content_type):
        # Diagnostic only: no mandatory readback and no nested publish retries.
        self.call('PUT', key, raw, {'content-type': content_type})


def report_identity(pointer):
    return {k: pointer[k] for k in REPORT_IDENTITY_FIELDS if k in pointer}


def validate_claim(claim, date, pointer=None):
    require(claim.get('date') == date and claim.get('channel_instance_id') == CHANNEL
            and all(isinstance(claim.get(k), str) and claim[k] for k in
                    ('task_id', 'attempt_id', 'content', 'publication_file_id', 'prefix')),
            'delivery_claim_conflict')
    if 'content_sha256' in claim:
        require(claim['content_sha256'] == sha(claim['content'].encode()), 'delivery_claim_conflict')
    identity = claim.get('report_identity')
    if identity is not None:
        require(identity.get('schema') == 'matrix_daily_ready_v1'
                and identity.get('date') == date and identity.get('scope') == 'three-repositories'
                and all(identity.get(k) == claim[k] for k in ('prefix', 'publication_file_id')),
                'delivery_claim_conflict')
    if pointer is not None:
        require(pointer.get('schema') == 'matrix_daily_ready_v1' and pointer.get('date') == date
                and pointer.get('scope') == 'three-repositories', 'delivery_ready_wrong_identity')
        require(all(claim[k] == pointer.get(k) for k in ('prefix', 'publication_file_id'))
                and (identity is None or identity == report_identity(pointer)), 'delivery_claim_conflict')


def validate_completion(stored, final):
    # Different observers may verify the same immutable ack at different times.
    # Every other field, including report identity and raw tool output, must agree.
    require(isinstance(stored, dict)
            and {k: v for k, v in stored.items() if k != 'verified_at_utc'}
            == {k: v for k, v in final.items() if k != 'verified_at_utc'},
            'delivery_completion_conflict')


def diagnostic(objects, key, value):
    try:
        objects.publish(key, json_bytes(value), 'application/json')
    except Exception:
        # Diagnostics are not delivery evidence and cannot veto real task/ack reads.
        pass


def find_native_receipt(api, final):
    """Reconcile a lost upload response by catalog/file reads, never re-upload."""
    name = 'matrix-security-delivery-' + final['date'].replace('-', '') + '.json'
    found = None
    for page in range(1, 101):
        result = api.data(api.request('/catalog/file/list', {
            'filters': [{'name': 'volume_id', 'values': ['130001']}],
            'page': page, 'page_size': 100}))
        rows = result.get('list')
        require(isinstance(rows, list), 'delivery_history_unreadable')
        for row in rows:
            if (row.get('origin_file_name') or row.get('name')) == name:
                fid = row.get('file_id', row.get('id'))
                raw = api.file(fid)
                require(raw == json_bytes(final), 'delivery_native_receipt_mismatch')
                found = dict(file_id=fid, bytes=len(raw), sha256=sha(raw), readback_verified=True,
                             catalog_attachment='verified')
        if len(rows) < 100:
            return found
    raise ValueError('delivery_history_pagination_incomplete')


def upload_receipt_file(api, name, raw):
    """Only upload bytes; the returned FID must be durable before catalog create."""
    boundary = 'moi' + uuid.uuid4().hex
    body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="'
            + name + '"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    body += raw + ('\r\n--' + boundary + '--\r\n').encode()
    result = json.loads(api.binary('/catalog/file/upload', raw=body,
                                   content_type='multipart/form-data; boundary=' + boundary))
    require(result.get('code') in ('OK', 0, 200), 'delivery_native_upload_rejected')
    fid = result.get('data', {}).get('file_id')
    require(isinstance(fid, str) and re.fullmatch(r'[0-9a-f-]{36}', fid),
            'delivery_native_upload_identity_invalid')
    return fid


def validate_receipt_file(identity, final, raw):
    require(isinstance(identity, dict)
            and identity.get('task_id') == final['task_id']
            and identity.get('bytes') == len(raw) and identity.get('sha256') == sha(raw)
            and isinstance(identity.get('file_id'), str)
            and re.fullmatch(r'[0-9a-f-]{36}', identity['file_id']),
            'delivery_native_receipt_conflict')


def local_receipt_file(final, identity=None):
    """Opaque FID handoff between supervisor children on this runner only."""
    path = Path('out/delivery') / ('native-receipt-upload-' + final['date'].replace('-', '') + '.json')
    try:
        saved = json.loads(path.read_bytes())
    except FileNotFoundError:
        saved = None
    if saved is not None:
        validate_receipt_file(saved, final, json_bytes(final))
        require(identity is None or saved == identity, 'delivery_native_receipt_conflict')
    if identity is None or saved is not None:
        return saved
    validate_receipt_file(identity, final, json_bytes(final))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as stream:
            stream.write(json_bytes(identity))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return identity


def native_receipt(api, objects, base, final, recovery=None):
    raw = json_bytes(final)
    saved = read_json(objects, base + '/native-delivery-receipt.json', missing=True)
    if saved is not None:
        require(checked_file(api, saved) == raw, 'delivery_native_receipt_mismatch')
        return saved
    recovery = {} if recovery is None else recovery
    identity_key = base + '/native-receipt-upload-file.json'
    saved_identity = read_json(objects, identity_key, missing=True)
    identity = recovery.get('file_identity') or local_receipt_file(final)
    if saved_identity is not None:
        validate_receipt_file(saved_identity, final, raw)
        require(identity is None or identity == saved_identity, 'delivery_native_receipt_conflict')
        identity = saved_identity
    artifact = recovery.get('artifact')
    if artifact is None and identity is None:
        artifact = find_native_receipt(api, final)
    if artifact is None and identity is None:
        # Persist upload permission separately: after an unknown upload or a
        # crash, subsequent observers may only discover the original native file.
        intent = recovery.setdefault('upload_intent', dict(
            task_id=final['task_id'], receipt_sha256=sha(raw), owner=str(uuid.uuid4())))
        intent_key = base + '/native-receipt-upload-claim.json'
        saved_intent = read_json(objects, intent_key, missing=True)
        if saved_intent is None:
            _, saved_intent = create_once(objects, intent_key, intent)
        require(all(saved_intent.get(k) == intent[k] for k in ('task_id', 'receipt_sha256')),
                'delivery_native_receipt_conflict')
        if saved_intent != intent or recovery.get('upload_started'):
            raise TimeoutError('delivery_native_upload_uncertain_read_only')
        # A lost intent confirmation is recoverable by this observer while it
        # still knows it has not attempted upload. After restart, read only.
        recovery['upload_started'] = True
        fid = upload_receipt_file(api, 'matrix-security-delivery-' + final['date'].replace('-', '') + '.json', raw)
        identity = dict(file_id=fid, bytes=len(raw), sha256=sha(raw), task_id=final['task_id'])
        # Retain a known FID even if its conditional PUT/readback times out.
        recovery['file_identity'] = identity
    if artifact is None:
        validate_receipt_file(identity, final, raw)
        # A runner-local atomic handoff survives a failed remote identity PUT.
        local_receipt_file(final, identity)
        if saved_identity is None:
            _, saved_identity = create_once(objects, identity_key, identity)
            require(saved_identity == identity, 'delivery_native_receipt_conflict')
        # Only a confirmed durable FID grants permission to attach this exact
        # file. An uncertain raw upload never reaches this path or uploads again.
        attach = recovery.setdefault('attach_intent', dict(
            file_id=identity['file_id'], task_id=final['task_id'], receipt_sha256=sha(raw),
            owner=str(uuid.uuid4())))
        attach_key = base + '/native-receipt-attach-claim.json'
        saved_attach = read_json(objects, attach_key, missing=True)
        if saved_attach is None:
            _, saved_attach = create_once(objects, attach_key, attach)
        require(all(saved_attach.get(k) == attach[k] for k in ('file_id', 'task_id', 'receipt_sha256')),
                'delivery_native_receipt_conflict')
        attachment = 'unknown'
        if saved_attach == attach and not recovery.get('attach_started'):
            recovery['attach_started'] = True
            try:
                api.request('/catalog/file/create', {'volume_id': 130001, 'file_ids': [identity['file_id']]})
            except Exception as exc:
                if not transient(exc):
                    raise
                # The mount may have committed. Only read this original FID.
            else:
                attachment = 'confirmed'
        try:
            require(checked_file(api, identity) == raw, 'delivery_native_receipt_mismatch')
        except Exception as exc:
            if str(exc) == 'moi_http_404' or isinstance(exc, urllib.error.HTTPError) and exc.code == 404:
                raise TimeoutError('delivery_native_file_unavailable_read_only') from None
            raise
        artifact = dict(file_id=identity['file_id'], bytes=len(raw), sha256=sha(raw), readback_verified=True,
                        catalog_attachment=attachment)
    recovery['artifact'] = artifact
    _, saved = create_once(objects, base + '/native-delivery-receipt.json', artifact)
    require(checked_file(api, saved) == raw, 'delivery_native_receipt_mismatch')
    return saved


def recover_claim(api, objects, date, claim, complete, deadline, poll_seconds, pointer=None):
    """Read only the original task; retry receipt persistence, never submission."""
    validate_claim(claim, date, pointer)
    api = RecoveryAPI(api, deadline)
    objects = RecoveryObjects(objects, deadline)
    base = 'daily/' + date.replace('-', '')
    final, stored = None, complete
    snapshot_attempted = complete is not None
    native_recovery = {}
    for _ in range(MAX_RECOVERY_ATTEMPTS):
        remaining(deadline)
        try:
            task = api.rpc('tasks/get', {'id': claim['task_id']}, str(uuid.uuid4()))
        except Exception as exc:
            if not transient(exc):
                raise
            pause(deadline, poll_seconds)
            continue
        state = task.get('status', {}).get('state')
        require(task.get('id') == claim['task_id'], 'delivery_runtime_identity_changed')
        if state == 'completed':
            verified = verify_send(task, claim)
            if 'report_identity' not in claim and (complete is None or 'report_identity' in complete):
                try:
                    ready = pointer if pointer is not None else read_json(objects, base + '/ready.json')
                except Exception as exc:
                    if not transient(exc):
                        raise
                    pause(deadline, poll_seconds)
                    continue
                validate_claim(claim, date, ready)
                claim = dict(claim, report_identity=report_identity(ready))
                verified = verify_send(task, claim)
            if final is None:
                final = verified  # Freeze receipt bytes across uncertain PUT/readback.
            else:
                validate_completion(final, verified)
            if stored is not None:
                validate_completion(stored, verified)
        require(state not in ('failed', 'input-required', 'auth-required', 'rejected', 'canceled', 'cancelled'),
                'delivery_task_terminal_do_not_resend')
        require(state in ('completed', 'submitted', 'working', 'running', 'queued', 'pending', 'unknown'),
                'delivery_task_state_invalid')
        if not snapshot_attempted:
            snapshot_attempted = True
            diagnostic(objects, base + '/delivery-task-private.json', task)
        if state != 'completed':
            pause(deadline, poll_seconds)
            continue
        try:
            remaining(deadline)
            if stored is None:
                # create_once uses If-None-Match even after a lost PUT/GET. A
                # winner is accepted only after ALL ack/claim fields agree.
                _, stored = create_once(objects, base + '/delivery-completed.json', final)
            validate_completion(stored, final)
            remaining(deadline)
            artifact = native_receipt(api, objects, base, stored, native_recovery)
            remaining(deadline)
            return dict(status='already_sent' if complete is not None else 'sent_verified',
                        sent=True, duplicate_prevented=True, successful_send_count=1,
                        tool_call_id=stored['tool_call_id'], task_id=stored['task_id'],
                        receipt_file_id=artifact['file_id'],
                        catalog_attachment=artifact.get('catalog_attachment', 'unknown'))
        except Exception as exc:
            if not transient(exc):
                raise
            pause(deadline, poll_seconds)
    raise ValueError('delivery_uncertain_read_original_task_only')


def recover_delivery(api, objects, date, poll_seconds=15, deadline_seconds=900):
    """Receipt-only entry point: no report downloads and no message/send path."""
    deadline = time.monotonic() + deadline_seconds
    base = 'daily/' + date.replace('-', '')
    bounded_objects = RecoveryObjects(objects, deadline)
    for _ in range(MAX_RECOVERY_ATTEMPTS):
        remaining(deadline)
        try:
            claim = read_json(bounded_objects, base + '/delivery-claim.json')
            require(claim is not None, 'delivery_existing_claim_required')
            complete = read_json(bounded_objects, base + '/delivery-completed.json', missing=True)
        except Exception as exc:
            if not transient(exc):
                raise
            pause(deadline, poll_seconds)
            continue
        return recover_claim(api, objects, date, claim, complete, deadline, poll_seconds)
    raise ValueError('delivery_uncertain_read_original_task_only')


def deliver(api, objects, date, preview=False, poll_seconds=15, deadline_seconds=900, not_before=None):
    base = 'daily/' + date.replace('-', '')
    complete = read_json(objects, base + '/delivery-completed.json', missing=True)
    if complete is not None and not preview:
        deadline = time.monotonic() + deadline_seconds
        claim = read_json(objects, base + '/delivery-claim.json')
        return recover_claim(api, objects, date, claim, complete, deadline, poll_seconds)
    pointer = read_json(objects, base + '/ready.json')
    require(pointer['schema'] == 'matrix_daily_ready_v1' and pointer['date'] == date and pointer['scope'] == 'three-repositories', 'delivery_ready_wrong_identity')
    bundle = check_bundle(api, objects, pointer['prefix'], date)
    require(bundle['root']['publication_file_id'] == pointer['publication_file_id']
            and bundle['publication_sha256'] == pointer['publication_sha256']
            and all(bundle['root'].get(k) == pointer[k] for k in ('run_id', 'commits') if k in pointer),
            'delivery_pointer_changed')
    content = compose(bundle, date)
    if preview:
        return dict(status='preview_passed', sent=False, pages_verified=bundle['pages_verified'], message_bytes=len(content.encode()))
    existing = read_json(objects, base + '/delivery-claim.json', missing=True)
    if existing is not None:
        deadline = time.monotonic() + deadline_seconds
        return recover_claim(api, objects, date, existing, None, deadline, poll_seconds, pointer)
    if not_before is not None:
        wait_until_delivery(date, not_before)
    prior_delivery(api, date)
    if not_before is not None:
        assert_send_time(date, not_before)
    deadline = time.monotonic() + deadline_seconds
    rid = 'matrix-daily-' + date.replace('-', '') + '-' + CHANNEL
    tid = 'art-' + sha((WORKSPACE + '\0' + rid).encode())[:48]
    prompt = ('用户已授权每天向既有“扫描漏洞”群发送已验收的安全日报。本次确定性校验已通过。只调用一次moi_wecom_robot_message，'
              'channel_instance_id=' + CHANNEL + '，msg_type=markdown。content逐字使用BEGIN_MESSAGE与END_MESSAGE之间正文（不含界标与分隔换行）。'
              '不得改写、拆分、换群、发其他消息、调用其他工具、读取凭据或扫描。超时或未知停止，禁止重试发送。'
              '控制器已在MinIO持久化全局当日唯一claim，负责回读真实任务并保存回执。完成工具调用后立即结束，不要再保存文件。\nBEGIN_MESSAGE\n'
              + content + '\nEND_MESSAGE')
    request = dict(model='kimi-k3', idempotencyKey=rid, message=dict(kind='message', role='user', messageId=rid, parts=[dict(kind='text', text=prompt)]))
    claim = dict(schema='matrix_daily_claim_v1', date=date, channel_instance_id=CHANNEL,
                 attempt_id=rid, task_id=tid, content=content, request=request,
                 publication_file_id=pointer['publication_file_id'], prefix=pointer['prefix'],
                 content_sha256=sha(content.encode()), report_identity=report_identity(pointer),
                 owner=os.environ.get('GITHUB_RUN_ID', 'manual') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1'),
                 at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    if not_before is not None:
        assert_send_time(date, not_before)
    elif os.environ.get('MATRIX_EXPECTED_REPORT_DATE') is not None:
        assert_expected_date(date)
    created, existing = create_once(RecoveryObjects(objects, deadline), base + '/delivery-claim.json', claim)
    claim = existing
    validate_claim(claim, date, pointer)
    require(claim['content'] == content, 'delivery_claim_conflict')
    if created:
        # Exactly one caller receives permission. Death or an uncertain response
        # permanently removes permission to submit, including on process restart.
        remaining(deadline)
        if not_before is not None:
            assert_send_time(date, not_before)
        elif os.environ.get('MATRIX_EXPECTED_REPORT_DATE') is not None:
            assert_expected_date(date)
        try:
            task = RecoveryAPI(api, deadline).rpc('message/send', claim['request'], claim['attempt_id'])
        except Exception:
            diagnostic(RecoveryObjects(objects, deadline), base + '/submission-uncertain.json',
                       dict(task_id=claim['task_id'], resubmit_allowed=False))
        else:
            require(task['id'] == claim['task_id'], 'delivery_runtime_identity_changed')
    return recover_claim(api, objects, date, claim, None, deadline, poll_seconds, pointer)


def delivery_not_before(date, value=None):
    floor = dt.datetime.combine(dt.date.fromisoformat(date), dt.time(10), LOCAL)
    if value is None:
        return floor
    try:
        at = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(at.tzinfo is not None and at.utcoffset() is not None, 'delivery_not_before_invalid')
        at = at.astimezone(LOCAL)
        require(at.date().isoformat() == date and at >= floor, 'delivery_not_before_invalid')
        return at
    except (ValueError, TypeError, AttributeError):
        raise ValueError('delivery_not_before_invalid') from None


def assert_expected_date(date):
    today = dt.datetime.now(LOCAL).date().isoformat()
    require(today == date, 'delivery_current_date_changed')
    expected = os.environ.get('MATRIX_EXPECTED_REPORT_DATE')
    require(expected is None or expected == today, 'delivery_expected_date_mismatch')


def assert_send_time(date, not_before):
    assert_expected_date(date)
    now = dt.datetime.now(LOCAL)
    require(now.date().isoformat() == date, 'delivery_current_date_changed')
    require(now.hour >= 10 and now >= not_before, 'delivery_before_ten_blocked')


def wait_until_delivery(date, not_before):
    while True:
        now = dt.datetime.now(LOCAL)
        require(now.date().isoformat() == date, 'delivery_current_date_changed')
        if now >= not_before:
            assert_send_time(date, not_before)
            return
        time.sleep(min(60, (not_before - now).total_seconds()))


def main():
    date = dt.datetime.now(LOCAL).date().isoformat()
    out = Path('out/delivery'); out.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    status = dict(date=date, sent=False, runtime_head=os.environ.get('MATRIX_RUNTIME_SHA'))
    try:
        assert_expected_date(date)
        preview = os.environ.get('MATRIX_DELIVERY_PREVIEW') == 'true'
        scheduled = os.environ.get('MATRIX_DELIVERY_NOT_BEFORE')
        not_before = delivery_not_before(date, scheduled)
        try:
            deadline_seconds = float(os.environ.get('MATRIX_DELIVERY_DEADLINE_SECONDS', '900'))
            require(math.isfinite(deadline_seconds) and deadline_seconds > 0, 'delivery_deadline_invalid')
        except (ValueError, TypeError):
            raise ValueError('delivery_deadline_invalid') from None
        api = DailyAPI(os.environ['MOI_API_KEY']); objects = Objects.from_workspace(api)
        if not preview and (os.environ.get('MATRIX_DELIVERY_RECOVER_ONLY') == 'true'
                or read_json(objects, 'daily/' + date.replace('-', '') + '/delivery-claim.json', missing=True) is not None):
            status.update(recover_delivery(api, objects, date, deadline_seconds=deadline_seconds))
        else:
            require(preview or scheduled is not None or dt.datetime.now(LOCAL).hour >= 10, 'delivery_before_ten_blocked')
            status.update(deliver(api, objects, date, preview=preview,
                                  deadline_seconds=deadline_seconds, not_before=not_before))
    except Exception as exc:
        status.update(status='failed', **error_fields(exc))
        if re.fullmatch('[a-z][a-z0-9_]{0,100}', str(exc)): status['safe_code'] = str(exc)
    status['seconds'] = round(time.monotonic() - start, 3)
    (out / 'status.json').write_bytes(json_bytes(status)); print(json.dumps(status), flush=True)
    return 1 if status['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
