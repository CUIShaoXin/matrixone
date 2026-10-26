"""Same-day verified delivery, with a non-expiring atomic claim per day/group.

An uncertain send is never submitted again. Recovery only reads the original
runtime task. The claim deliberately favors a missed delivery over a duplicate.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

from cloud_daily import DailyAPI, WORKSPACE, json_bytes, verify_rag
from cloud_publish import verify_batch
from resilient_storage import Objects, SignedObjects, verify_login_free
from api_port_review import llm_calls
from pipeline_telemetry import span, error_fields

LOCAL = dt.timezone(dt.timedelta(hours=8))
REPOS = ('matrixone', 'taas', 'matrixflow')
NAMES = dict(zip(REPOS, ('MatrixOne', 'TaaS', 'MatrixFlow')))
CHANNEL = '09567f53-8dad-41d8-842e-2e269a6c86e2'
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
        SignedObjects.call(objects, 'PUT', key, raw, {
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
    kb = [v for k, v in reviews['model_tasks'].items() if k.endswith('_kb_final_report_scope_v2')]
    require(len(kb) == 1 and kb[0].get('task_id'), 'delivery_final_kb_task_missing')
    task = api.rpc('tasks/get', {'id': kb[0]['task_id']}, str(uuid.uuid4()))
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
                found[v['callId']] = v
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
    result = results[cid]['output']; output = result.get('output', result)
    require(output.get('ok') is True and output.get('status') == 'COMPLETED' and output.get('data', {}).get('ok') is True and output.get('request_id') == cid, 'delivery_real_tool_receipt_missing')
    return dict(schema='matrix_daily_delivery_v1', date=claim['date'], scope='three-repositories',
                sent=True, status='sent', channel_instance_id=CHANNEL, task_id=task['id'],
                attempt_id=claim['attempt_id'], tool_call_id=cid, tool_output=result,
                content=claim['content'], content_sha256=sha(claim['content'].encode()),
                publication_file_id=claim['publication_file_id'], prefix=claim['prefix'],
                verified_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())


def native_receipt(api, objects, base, final):
    saved = read_json(objects, base + '/native-delivery-receipt.json', missing=True)
    if saved:
        require(checked_file(api, saved) == json_bytes(final), 'delivery_native_receipt_mismatch')
        return saved
    artifact = api.upload('matrix-security-delivery-' + final['date'].replace('-', '') + '.json', json_bytes(final))
    objects.publish(base + '/native-delivery-receipt.json', json_bytes(artifact), 'application/json')
    return artifact


def deliver(api, objects, date, preview=False, poll_seconds=15, deadline_seconds=900):
    base = 'daily/' + date.replace('-', '')
    complete = read_json(objects, base + '/delivery-completed.json', missing=True)
    if complete:
        task = api.rpc('tasks/get', {'id': complete['task_id']}, str(uuid.uuid4()))
        claim = read_json(objects, base + '/delivery-claim.json')
        verified = verify_send(task, claim)
        require(complete['date'] == date and complete['content_sha256'] == verified['content_sha256'] and complete['tool_call_id'] == verified['tool_call_id'], 'delivery_saved_completion_mismatch')
        artifact = native_receipt(api, objects, base, complete)
        return dict(status='already_sent', sent=True, duplicate_prevented=True, task_id=complete['task_id'], tool_call_id=complete['tool_call_id'], receipt_file_id=artifact['file_id'])
    pointer = read_json(objects, base + '/ready.json')
    require(pointer['schema'] == 'matrix_daily_ready_v1' and pointer['date'] == date and pointer['scope'] == 'three-repositories', 'delivery_ready_wrong_identity')
    bundle = check_bundle(api, objects, pointer['prefix'], date)
    require(bundle['root']['publication_file_id'] == pointer['publication_file_id'] and bundle['publication_sha256'] == pointer['publication_sha256'], 'delivery_pointer_changed')
    content = compose(bundle, date)
    if preview:
        return dict(status='preview_passed', sent=False, pages_verified=bundle['pages_verified'], message_bytes=len(content.encode()))
    existing = read_json(objects, base + '/delivery-claim.json', missing=True)
    created = False
    if existing is None:
        prior_delivery(api, date)
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
                     owner=os.environ.get('GITHUB_RUN_ID', 'manual') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1'),
                     at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        created, existing = create_once(objects, base + '/delivery-claim.json', claim)
    claim = existing
    require(claim['date'] == date and claim['channel_instance_id'] == CHANNEL and claim['publication_file_id'] == pointer['publication_file_id'] and claim['content'] == content, 'delivery_claim_conflict')
    started = time.monotonic()
    if created:
        # Exactly one caller gets permission to submit. An exception, process
        # death, or uncertain response permanently removes permission to submit.
        try:
            task = api.rpc('message/send', claim['request'], claim['attempt_id'])
            require(task['id'] == claim['task_id'], 'delivery_runtime_identity_changed')
        except Exception:
            objects.publish(base + '/submission-uncertain.json', json_bytes(dict(task_id=claim['task_id'], resubmit_allowed=False)), 'application/json')
    while time.monotonic() - started < deadline_seconds:
        try:
            task = api.rpc('tasks/get', {'id': claim['task_id']}, str(uuid.uuid4()))
        except Exception:
            # Read-only recovery only; no second message/send request.
            time.sleep(poll_seconds)
            continue
        state = task.get('status', {}).get('state')
        objects.publish(base + '/delivery-task-private.json', json_bytes(task), 'application/json')
        if state == 'completed':
            final = verify_send(task, claim)
            _, stored = create_once(objects, base + '/delivery-completed.json', final)
            require(stored['task_id'] == final['task_id'] and stored['content_sha256'] == final['content_sha256'], 'delivery_completion_conflict')
            artifact = native_receipt(api, objects, base, stored)
            return dict(status='sent_verified', sent=True, successful_send_count=1, tool_call_id=final['tool_call_id'], task_id=final['task_id'], receipt_file_id=artifact['file_id'])
        require(state not in ('failed', 'input-required', 'rejected', 'canceled', 'cancelled'), 'delivery_task_terminal_do_not_resend')
        time.sleep(poll_seconds)
    raise ValueError('delivery_uncertain_read_original_task_only')


def main():
    date = dt.datetime.now(LOCAL).date().isoformat()
    out = Path('out/delivery'); out.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    status = dict(date=date, sent=False, runtime_head=os.environ.get('MATRIX_RUNTIME_SHA'))
    try:
        require(dt.datetime.now(LOCAL).hour >= 10 or os.environ.get('MATRIX_DELIVERY_PREVIEW') == 'true', 'delivery_before_ten_blocked')
        api = DailyAPI(os.environ['MOI_API_KEY']); objects = Objects.from_workspace(api)
        status.update(deliver(api, objects, date, preview=os.environ.get('MATRIX_DELIVERY_PREVIEW') == 'true'))
    except Exception as exc:
        status.update(status='failed', **error_fields(exc))
        if re.fullmatch('[a-z][a-z0-9_]{0,100}', str(exc)): status['safe_code'] = str(exc)
    status['seconds'] = round(time.monotonic() - start, 3)
    (out / 'status.json').write_bytes(json_bytes(status)); print(json.dumps(status), flush=True)
    return 1 if status['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
