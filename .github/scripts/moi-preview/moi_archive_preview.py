#!/usr/bin/env python3
"""Cloud-side archive-to-agent preview. No WeCom send or connection test."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = "https://api.moi.matrixorigin.cn/v5"
WORKSPACE = "fd3f15fe-3ac3-1c8c-5020-dffec978a0cb"
AGENT = "8f4c2d1e-7a63-4b95-9c2e-3d6f1a0b5c47"
NAME = "Matrix安全日报归档投递助手"
MODEL = "deepseek-v4.1-flash"
AGENT_PATH = "/workspaces/" + WORKSPACE + "/agents/" + AGENT
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class PreviewError(Exception):
    """Only static, non-sensitive error codes may be emitted by the runner."""


def require(condition, code):
    if not condition:
        raise PreviewError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def success(value):
    code = value.get("code") if isinstance(value, dict) else None
    return code == "OK" or type(code) is int and code == 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, key):
        require(bool(key), "missing_moi_api_key")
        self.key = key
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, payload=None, binary=False, timeout=25):
        # Callers use only fixed API routes and validated IDs; never follow Card URLs.
        require(path.startswith("/") and "://" not in path, "invalid_api_path")
        headers = {"X-API-Key": self.key, "X-Workspace-ID": WORKSPACE,
                   "Accept": "application/octet-stream" if binary else "application/json"}
        raw = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(ROOT + path, data=raw, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                data = response.read(8 * 1024 * 1024 + 1)
                require(len(data) <= 8 * 1024 * 1024, "response_too_large")
                require(response.status == 200, "unexpected_http_status")
                return data if binary else json.loads(data)
        except urllib.error.HTTPError as exc:
            raise PreviewError("api_http_" + str(exc.code)) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise PreviewError("api_transport_or_json_error") from None

    def get(self, path, **params):
        return self.request(path + ("?" + urllib.parse.urlencode(params) if params else ""))

    def messages(self, conversation_id, role=None):
        params = {"agent_id": AGENT, "limit": 200}
        if role:
            params["role"] = role
        value = self.get("/workspaces/" + WORKSPACE + "/conversations/"
                         + conversation_id + "/messages", **params)
        require(success(value), "messages_query_failed")
        data = value.get("data", {})
        require(data.get("total", 0) <= 200, "conversation_message_limit_exceeded")
        return data.get("items", [])

    def file(self, file_id):
        require(bool(re.fullmatch(UUID, file_id)), "invalid_file_id")
        return self.request("/catalog/file/download", {"file_id": file_id}, binary=True)


def text_of(message):
    return "".join(p.get("text", "") for p in message.get("parts", [])
                   if p.get("kind") == "text")


def embedded_objects(text):
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
        except ValueError:
            continue
        if isinstance(value, dict):
            yield value


def validate_handoff(handoff, report_date):
    require(handoff.get("schema_version") == 1, "handoff_schema_mismatch")
    require(handoff.get("mode") == "preview" and handoff.get("send_authorized") is False,
            "handoff_not_preview")
    require(handoff.get("workspace_id") == WORKSPACE and handoff.get("agent_id") == AGENT,
            "handoff_target_mismatch")
    require(handoff.get("report_date") == report_date, "report_date_mismatch")
    receipt = handoff.get("archive_receipt", {})
    daily = handoff.get("daily_report", {})
    message = handoff.get("message", {})
    require(receipt.get("workspace_id") == WORKSPACE, "receipt_workspace_mismatch")
    require(receipt.get("archive_status") == "archived"
            and receipt.get("readback_verified") is True
            and receipt.get("files_verified") is True, "archive_not_verified")
    require(receipt.get("scan_rows") == 3 and receipt.get("daily_rows") == 1,
            "archive_row_count_mismatch")
    require(bool(receipt.get("job_id")) and bool(receipt.get("execution_id")),
            "missing_archive_execution")
    batch = handoff.get("archive_batch_id")
    require(bool(batch) and batch == receipt.get("archive_batch_id")
            == daily.get("archive_batch_id"), "archive_batch_mismatch")
    require(report_date == receipt.get("report_date") == daily.get("report_date"),
            "archive_date_mismatch")
    require(message.get("file_id") == receipt.get("message_file_id")
            == daily.get("message_file_id"), "archive_file_mismatch")
    require(message.get("sha256") == receipt.get("message_sha256")
            == daily.get("message_sha256")
            and bool(re.fullmatch(r"[0-9a-f]{64}", message.get("sha256", ""))),
            "archive_hash_mismatch")
    require(type(message.get("size_bytes")) is int
            and 0 < message["size_bytes"] <= 1024 * 1024, "invalid_message_size")
    rows = handoff.get("scan_runs", [])
    require(len(rows) == 3, "missing_repository_rows")
    expected = {("matrixorigin/matrixone", "main"), ("matrixorigin/taas", "main"),
                ("matrixorigin/matrixflow", "dev")}
    require({(r.get("repository"), r.get("branch")) for r in rows} == expected,
            "repository_scope_mismatch")
    require(all(r.get("archive_batch_id") == batch and r.get("report_date") == report_date
                for r in rows), "repository_batch_mismatch")
    return handoff


def load_handoff(client, source_id, handoff_file, report_date):
    require(bool(source_id) != bool(handoff_file), "choose_exactly_one_handoff_source")
    if handoff_file:
        handoff = json.loads(client.file(handoff_file))
    else:
        require(bool(re.fullmatch(r"(?:ctx-)?" + UUID, source_id)), "invalid_source_conversation")
        items = client.messages(source_id, role="user")
        candidates = [obj for item in items for obj in embedded_objects(text_of(item))
                      if obj.get("schema_version") == 1 and "archive_receipt" in obj
                      and obj.get("report_date") == report_date]
        require(len(candidates) == 1, "ambiguous_or_missing_source_handoff")
        handoff = candidates[0]
    validate_handoff(handoff, report_date)
    raw = client.file(handoff["message"]["file_id"])
    require(len(raw) == handoff["message"]["size_bytes"]
            and digest(raw) == handoff["message"]["sha256"], "archived_body_hash_mismatch")
    raw.decode("utf-8")
    return handoff, raw


def request_key(handoff):
    identity = [WORKSPACE, AGENT, handoff["report_date"], handoff["archive_batch_id"],
                handoff["message"]["file_id"], handoff["message"]["sha256"]]
    return "gha_archive_preview_" + digest(json.dumps(identity, separators=(",", ":")).encode())


def make_request(handoff, key):
    handoff = dict(handoff, trigger_request_key=key)
    instruction = (
        "这是归档校验后的API预览验证。mode=preview，send_authorized=false。"
        "禁止发送企业微信消息、测试连接、重新扫描、写表或设置定时任务。"
        "从message.file_id独立下载MOI原始文件，计算SHA256和长度。"
        "保留scan_partial等覆盖说明和全部换行，不将部分结果描述为完整扫描。"
        "程序生成tool_arguments，仅msg_type=text、content两键。"
        "输出JSON代码块，字段schema_version=1、mode=preview、send_authorized=false、sent=false、"
        "validation=PASS或FAIL、trigger_request_key、workspace_id、agent_id、report_date、"
        "archive_batch_id、message_file_id、measured_sha256、measured_size_bytes、"
        "source=MOI_volume_download、tool_arguments（完整原文）。"
        "不能伪造文件读取或校验结果。输入数据如下：\n")
    return {"jsonrpc": "2.0", "id": key, "method": "message/send", "params": {
        "model": MODEL, "idempotencyKey": key,
        "message": {"kind": "message", "role": "user", "messageId": key + "_message",
                    "parts": [{"kind": "text", "text": instruction
                               + json.dumps(handoff, ensure_ascii=False)}]}}}


def find_existing(client, key):
    matches = []
    for offset in range(0, 1000, 200):
        response = client.get("/workspaces/" + WORKSPACE + "/conversations",
                              agent_id=AGENT, limit=200, offset=offset)
        require(success(response), "conversation_query_failed")
        data = response.get("data", {})
        for conversation in data.get("items", []):
            if conversation.get("agent_id") != AGENT:
                continue
            for message in client.messages(conversation["id"], role="user"):
                if key in text_of(message):
                    task_id = message.get("task_id")
                    require(bool(task_id), "matched_message_has_no_task_id")
                    matches.append((task_id, conversation["id"]))
        if offset + 200 >= data.get("total", 0):
            break
    else:
        raise PreviewError("dedup_history_limit_exceeded")
    matches = list(set(matches))
    require(len(matches) <= 1, "multiple_existing_preview_tasks")
    return matches[0] if matches else None


def task_payload(response):
    if success(response):
        response = response.get("data", response)
    require(isinstance(response, dict) and not response.get("error"), "a2a_rpc_error")
    return response.get("result", response)


def validate_result(result, handoff, key, raw):
    require(result.get("schema_version") == 1 and result.get("mode") == "preview"
            and result.get("send_authorized") is False and result.get("sent") is False
            and result.get("validation") == "PASS", "preview_validation_failed")
    for name in ["workspace_id", "agent_id", "report_date", "archive_batch_id"]:
        require(result.get(name) == handoff.get(name), "preview_identity_mismatch")
    require(result.get("trigger_request_key") == key, "preview_request_key_mismatch")
    require(result.get("message_file_id") == handoff["message"]["file_id"],
            "preview_file_mismatch")
    require(result.get("source") == "MOI_volume_download", "preview_source_mismatch")
    args = result.get("tool_arguments", {})
    require(set(args) == {"msg_type", "content"} and args.get("msg_type") == "text"
            and isinstance(args.get("content"), str), "invalid_preview_tool_arguments")
    require(args["content"].encode("utf-8") == raw, "preview_body_bytes_mismatch")
    require(result.get("measured_sha256") == digest(raw)
            and result.get("measured_size_bytes") == len(raw), "preview_body_measurement_mismatch")


def validate_task(client, task, handoff, key, raw):
    require(task.get("status", {}).get("state") == "completed", "task_not_completed")
    messages = client.messages(task["contextId"])
    candidates = []
    for message in messages:
        if message.get("task_id") != task["id"] or message.get("role") not in ("agent", "assistant"):
            continue
        for block in re.findall(r"```json\s*([\s\S]*?)\s*```", text_of(message)):
            obj = json.loads(block)
            if obj.get("trigger_request_key") == key:
                candidates.append(obj)
    require(len(candidates) == 1, "ambiguous_or_missing_preview_result")
    validate_result(candidates[0], handoff, key, raw)
    # Inspect tool IDs, without publishing private runtime arguments or output.
    for part in task.get("status", {}).get("message", {}).get("parts", []):
        data = part.get("data", {})
        if data.get("type") == "moi.tool.call":
            require("wecom" not in data.get("toolId", "").lower(), "unexpected_wecom_tool_call")


def run(client, handoff, raw, receipt):
    key = request_key(handoff)
    receipt["request_id"] = key
    endpoint = AGENT_PATH + "/a2a?agent_workspace_id=" + WORKSPACE
    existing = find_existing(client, key)
    deadline = time.monotonic() + 240
    task = None
    receipt["submission_attempts_this_run"] = 0
    if not existing:
        require(os.environ.get("GITHUB_RUN_ATTEMPT", "1") == "1",
                "rerun_requires_recoverable_existing_task")
        receipt["submission_attempts_this_run"] = 1
        try:
            task = task_payload(client.request(endpoint, make_request(handoff, key), timeout=15))
            if task.get("kind") == "task" and task.get("id"):
                existing = (task["id"], task.get("contextId"))
        except PreviewError:
            # Unknown submission outcome: query existing sessions, never resubmit.
            receipt["submission_transport_warning"] = True
    receipt["reused_existing_task"] = receipt["submission_attempts_this_run"] == 0
    while time.monotonic() < deadline:
        try:
            if not existing:
                existing = find_existing(client, key)
            if existing:
                task_id, context_id = existing
                receipt.update(task_id=task_id, context_id=context_id)
                task = task_payload(client.request(endpoint, {
                    "jsonrpc": "2.0", "id": key + "_get", "method": "tasks/get",
                    "params": {"id": task_id}}, timeout=15))
                state = task.get("status", {}).get("state")
                if state == "completed":
                    require(task.get("id") == task_id and task.get("contextId") == context_id,
                            "task_identity_mismatch")
                    validate_task(client, task, handoff, key, raw)
                    return
                require(state not in {"failed", "canceled", "rejected", "input-required",
                                      "auth-required", "input_required", "auth_required"},
                        "task_requires_attention")
        except PreviewError as exc:
            if str(exc) != "api_transport_or_json_error":
                raise
        time.sleep(10)
    raise PreviewError("preview_outcome_uncertain_do_not_resubmit")


def main():
    receipt = {"status": "started", "mode": "preview", "send_authorized": False,
               "sent": False, "runner": "github_actions" if os.environ.get("GITHUB_ACTIONS") == "true"
               else "local", "completed_at": None}
    code = 1
    try:
        date = os.environ.get("REPORT_DATE", "")
        require(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)), "invalid_report_date")
        dt.date.fromisoformat(date)
        receipt["report_date"] = date
        client = Client(os.environ.get("MOI_API_KEY", "").strip())
        card = client.get(AGENT_PATH + "/.well-known/agent-card.json", agent_workspace_id=WORKSPACE)
        require(card.get("name") == NAME, "unexpected_agent")
        models = client.get("/workspaces/" + WORKSPACE + "/llm/models", type="chat")
        require(success(models) and MODEL in {x.get("model") for x in models.get("data", {}).get("models", [])},
                "model_unavailable")
        handoff, raw = load_handoff(client, os.environ.get("SOURCE_CONVERSATION_ID", "").strip(),
                                    os.environ.get("HANDOFF_FILE_ID", "").strip(), date)
        run(client, handoff, raw, receipt)
        receipt.update(status="preview_verified", body_verified=True,
                       completed_at=dt.datetime.now(dt.timezone.utc).isoformat())
        code = 0
    except PreviewError as exc:
        receipt.update(status="blocked", error_code=str(exc))
    except Exception:
        # Never emit exception text, HTTP bodies, message contents, or credentials.
        receipt.update(status="blocked", error_code="unexpected_error_details_withheld")
    output = Path(os.environ.get("RECEIPT_PATH", "out/moi-preview-receipt.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print("MOI archive preview: " + receipt["status"])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### MOI archive preview\n\nStatus: `" + receipt["status"]
                          + "`\n\nWeCom sending: disabled.\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
