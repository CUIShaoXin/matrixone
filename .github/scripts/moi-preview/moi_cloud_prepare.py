#!/usr/bin/env python3
"""Read per-repository MOI uploads, verify the archive, then hand off.

Private data stays on the ephemeral runner and in the fixed MOI workspace.
Only a sanitized receipt is suitable for a public GitHub artifact.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "moi-scan"))
import moi_repo_scan as exchange
import archive_schema as schema
import moi_archive_preview as preview

LOCAL = dt.timezone(dt.timedelta(hours=8))
WORKSPACE = preview.WORKSPACE
VOLUME = 130001
WORKFLOW = "b7c59a89-7755-5611-8cfb-994f6cebc8d6"
PREFIX = "/workflow/v2/workflow-apps/" + WORKFLOW
CONFIG = exchange.CONFIG
require = preview.require
Error = preview.PreviewError
sha = preview.digest


def now():
    return dt.datetime.now(LOCAL)


def pack(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def data(response):
    require(response.get("code") == "OK" or type(response.get("code")) is int
            and response["code"] in (0, 200), "moi_api_rejected")
    return response.get("data")


class MOI(exchange.MOI):
    def sql(self, query):
        query_id = data(self.request("/query/execute", {
            "db_name": "security_scan_archive", "query": query, "limit": 10}))["query_id"]
        for _ in range(20):
            state = data(self.request("/query/describe", {"query_id": query_id}))
            if state.get("status") == "success":
                result = data(self.request("/query/result", {
                    "statement_id": state["statement_id"], "limit": 10}))
                names = [c["name"] for c in result.get("columns", [])]
                return [dict(zip(names, [c["String"] if c.get("Valid") else None for c in row]))
                        for row in result.get("result", [])]
            require(state.get("status") == "running", "independent_sql_failed")
            time.sleep(2)
        raise Error("independent_sql_timeout")



def collect_uploads(moi, date, current):
    scans = {}
    for name in schema.REPOS:
        try:
            scans[name] = exchange.read_scan(moi, name, date, current)
        except exchange.ScanError as exc:
            scans[name] = dict(name=name, repository="matrixorigin/" + name,
                branch=CONFIG[name][1], commit="", status="scan_failed", error=str(exc),
                hits=None, unique_ids=None, packages=None, run=None, raw=None, stderr=None)
        except (KeyError, TypeError, ValueError):
            scans[name] = dict(name=name, repository="matrixorigin/" + name,
                branch=CONFIG[name][1], commit="", status="scan_failed", error="invalid_scan_manifest",
                hits=None, unique_ids=None, packages=None, run=None, raw=None, stderr=None)
    return scans


def body_for(scans, date):
    sections = ["【Matrix 安全日报 " + date + "】"]
    for name in schema.REPOS:
        scan = scans[name]
        lines = [scan["repository"] + "（" + scan["branch"] + "）"]
        status = scan["status"]
        labels = {"clean": "未检出已知漏洞", "vulnerabilities_found": "检出已知漏洞",
                  "scan_partial": "部分依赖分析完成（覆盖不完整）", "scan_failed": "扫描或证据校验失败，统计未知",
                  "pending": "今日扫描尚未完成，统计未知", "unavailable": "今日证据不可用或访问权限不足，统计未知"}
        lines.append("结果：" + labels[status])
        if status in {"clean", "vulnerabilities_found", "scan_partial"}:
            lines += ["扫描提交：" + scan["commit"][:12],
                      f"漏洞命中：{scan['hits']} 条；唯一漏洞标识：{scan['unique_ids']} 个；涉及包：{scan['packages']} 个。",
                      "范围：" + scan["coverage"]]
        if scan.get("run"):
            lines.append("报告：https://github.com/" + CONFIG[name][0] + "/actions/runs/" + str(scan["run"]["id"]))
        if scan.get("error"):
            lines.append("状态码：" + scan["error"])
        sections.append("\n".join(lines))
    return ("\n\n".join(sections) + "\n").encode()


def archived_rows(moi, payload):
    batch = schema.sql_literal(payload["archive_batch_id"])
    scans = moi.sql("SELECT * FROM security_scan_archive.scan_runs WHERE archive_batch_id=" + batch)
    daily = moi.sql("SELECT * FROM security_scan_archive.daily_reports WHERE archive_batch_id=" + batch)
    require(len(scans) == 3 and len(daily) == 1, "archive_readback_row_count_mismatch")
    expected = {payload[n]["repository"]: payload[n] for n in schema.REPOS}
    require({r["repository"] for r in scans} == set(expected), "archive_readback_repository_mismatch")
    for row in scans:
        for key, value in expected[row["repository"]].items():
            require(row.get(key) == (None if value is None else str(value)), "archive_scan_readback_mismatch")
    for key, value in payload["daily_report"].items():
        require(daily[0].get(key) == str(value), "archive_daily_readback_mismatch")
    return scans, daily[0]


def workflow_run(moi, payload):
    definition = data(moi.get(PREFIX))["workflow"]
    require(definition["id"] == WORKFLOW and definition["name"] == "Matrix_三仓库扫描结果归档"
            and definition["execution_mode"] == "one_shot", "unexpected_archive_workflow")
    expected_nodes = {"step_" + str(i) for i in range(1, 6)}
    nodes = definition.get("workflow", {}).get("nets", {}).get("root", {}).get("nodes", {})
    require(set(nodes) == expected_nodes | {"__start", "__end"}
            and all(nodes[n]["id"] == "moi:data.sql.process" for n in expected_nodes), "archive_workflow_definition_changed")
    inputs = schema.sql_inputs(payload)
    values = {"sql": inputs["matrixone_sql"], **{k: inputs[k] for k in
              ("taas_sql", "matrixflow_sql", "daily_report_sql", "verify_sql")}}
    require(all(payload["archive_batch_id"] in sql for sql in values.values()), "sql_batch_mismatch")
    result = data(moi.request(PREFIX + "/executions", {"values": values,
                  "replace_saved_defaults": True, "trigger_now": True}))
    run = result["workflow_run"]
    require(run["workflow_id"] == WORKFLOW and run["execution_mode"] == "one_shot", "wrong_archive_execution")
    job_id = run["execution_id"]
    require(bool(re.fullmatch(preview.UUID, job_id)), "invalid_archive_job_id")
    for _ in range(90):
        execution = data(moi.get(PREFIX + "/executions/" + job_id + "/result"))["result"]
        state = execution["status"]
        if state in {"completed", "success", "succeeded"}:
            require(bool(execution.get("moi_case_id")), "missing_native_execution_id")
            return job_id, execution["moi_case_id"]
        require(state not in {"failed", "cancelled", "canceled", "paused"}, "archive_workflow_failed")
        time.sleep(2)
    raise Error("archive_execution_uncertain_do_not_restart")


def archive(moi, scans, date):
    body = body_for(scans, date)
    identity = pack({n: {k: v for k, v in scans[n].items() if k not in {"raw", "stderr"}} for n in schema.REPOS})
    batch = "cloud_daily_" + date.replace("-", "") + "_" + sha(identity + body)[:16]
    stamp = now().isoformat(timespec="seconds")
    files, rows = [], {}

    def upload(label, raw):
        name = batch + "-" + sha(raw)[:12] + "-" + label
        file_id = moi.upload(name, raw)
        files.append(dict(name=name, file_id=file_id, sha256=sha(raw), size=len(raw)))
        return file_id

    for name in schema.REPOS:
        scan = scans[name]
        evidence = {k: v for k, v in scan.items() if k not in {"raw", "stderr"}}
        run = scan.get("run") or {}
        raw_id = upload(name + "-osv.json", scan["raw"]) if scan.get("raw") is not None else ""
        stderr_id = upload(name + "-stderr.txt", scan["stderr"]) if scan.get("stderr") is not None else ""
        evidence_id = upload(name + "-evidence.json", pack(evidence))
        rows[name] = dict(archive_id=batch + "_" + name, archive_batch_id=batch, report_date=date,
            repository=scan["repository"], branch=scan["branch"], commit_sha=scan["commit"],
            scan_started_at=scan.get("started_at", ""), scan_finished_at=scan.get("finished_at", ""),
            execution_source="github_actions:" + CONFIG[name][0],
            source_run_id=str(run.get("id", "")),
            source_run_attempt=str(run.get("run_attempt", "")),
            scan_status=scan["status"], vulnerability_hits=scan["hits"], unique_ids=scan["unique_ids"],
            packages=scan["packages"], coverage_note=scan.get("coverage", "No verified scan result"),
            error_code=scan.get("error", ""), raw_file_id=raw_id, stderr_file_id=stderr_id,
            evidence_file_id=evidence_id, report_sha256=sha(scan["raw"]) if raw_id else "",
            source_url="https://github.com/" + CONFIG[name][0] + ("/actions/runs/" + str(run["id"]) if run else "/tree/" + (scan["commit"] or CONFIG[name][1])),
            archived_at=stamp, artifact_status="files_uploaded" if raw_id and stderr_id else "evidence_only",
            scanner_version=scan.get("scanner_version", "2.7.0"))
    message_id = upload("daily-report.txt", body)
    status = "archived" if all(rows[n]["artifact_status"] == "files_uploaded" for n in schema.REPOS) else "archived_with_gaps"
    daily = dict(archive_batch_id=batch, report_date=date, prepared_at=stamp,
                 **{n + "_archive_id": rows[n]["archive_id"] for n in schema.REPOS},
                 message_file_id=message_id, message_sha256=sha(body), archive_status=status,
                 archive_error="" if status == "archived" else "one_or_more_current_sources_unavailable",
                 workflow_execution_id="", archived_at=stamp)
    payload = schema.validate(dict(archive_batch_id=batch, daily_report=daily, daily_report_text=body.decode(), **rows))
    job_id, execution_id = workflow_run(moi, payload)
    moi.sql("UPDATE security_scan_archive.daily_reports SET workflow_execution_id=" + schema.sql_literal(execution_id)
            + " WHERE archive_batch_id=" + schema.sql_literal(batch))
    daily["workflow_execution_id"] = execution_id
    archived_rows(moi, payload)
    # Re-read every file independently after indexing, including large raw OSV reports.
    for entry in files:
        raw = moi.file(entry["file_id"])
        require(sha(raw) == entry["sha256"] and len(raw) == entry["size"], "final_file_verification_failed")
    receipt = dict(workspace_id=WORKSPACE, workflow_id=WORKFLOW, archive_batch_id=batch,
                   report_date=date, job_id=job_id, execution_id=execution_id, scan_rows=3,
                   daily_rows=1, message_file_id=message_id, message_sha256=sha(body),
                   archive_status=status, readback_verified=True, files_verified=True)
    # The preview validator requires a verified archive. Gaps remain explicit in rows/body.
    handoff = dict(schema_version=1, mode="preview", send_authorized=False,
                   workspace_id=WORKSPACE, agent_id=preview.AGENT, report_date=date,
                   archive_batch_id=batch, archive_receipt=receipt, daily_report=daily,
                   scan_runs=list(rows.values()), message=dict(file_id=message_id,
                   sha256=sha(body), size_bytes=len(body)), file_verification=files)
    return handoff


def main():
    os.umask(0o077)
    receipt = dict(status="started", runner="github_actions", sent=False, mode="preview")
    exit_code = 1
    try:
        require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == "CUIShaoXin/matrixone",
                "unexpected_runner_or_repository")
        date = os.environ.get("REPORT_DATE", "").strip() or now().date().isoformat()
        require(date == now().date().isoformat(), "only_current_day_preparation_allowed")
        receipt["report_date"] = date
        moi = MOI(os.environ.get("MOI_API_KEY", ""))
        ready_name = "cloud-ready-" + date.replace("-", "") + ".json"
        ready_id = moi.named_file(ready_name)
        if ready_id:
            handoff = json.loads(moi.file(ready_id))
            preview.validate_handoff(handoff, date)
            raw = moi.file(handoff["message"]["file_id"])
            require(sha(raw) == handoff["message"]["sha256"] and len(raw) == handoff["message"]["size_bytes"], "cached_cloud_body_mismatch")
            require(len(handoff.get("file_verification", [])) >= 4, "missing_cloud_file_verification")
            for entry in handoff["file_verification"]:
                raw_file = moi.file(entry["file_id"])
                require(sha(raw_file) == entry["sha256"] and len(raw_file) == entry["size"], "cached_cloud_file_mismatch")
            archived_rows(moi, dict(archive_batch_id=handoff["archive_batch_id"], daily_report=handoff["daily_report"],
                                   **{r["repository"].split("/")[-1]: r for r in handoff["scan_runs"]}))
            receipt["reused_existing_ready"] = True
        else:
            require(os.environ.get("GITHUB_RUN_ATTEMPT", "1") == "1", "rerun_requires_verified_cloud_ready")
            if os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true":
                require(now().time() < dt.time(9, 50), "daily_preparation_window_missed")
            scans = collect_uploads(moi, date, now())
            deadline = now().replace(hour=9, minute=50, second=0, microsecond=0)
            while os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true" and now() < deadline and any(
                    s["status"] == "pending" for s in scans.values()):
                time.sleep(min(60, max(1, (deadline - now()).total_seconds())))
                scans = collect_uploads(moi, date, now())
            if os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true":
                require(now().time() < dt.time(9, 55), "daily_archival_window_missed")
            if os.environ.get("WAIT_FOR_CLOUD_RUNS") != "true":
                require(not any(row["status"] == "pending" for row in scans.values()),
                        "repository_uploads_not_ready")
            lock_name = "cloud-preparation-lock-" + date.replace("-", "") + ".json"
            require(moi.named_file(lock_name) is None, "existing_preparation_requires_recovery")
            moi.upload(lock_name, pack(dict(report_date=date, github_run_id=os.environ["GITHUB_RUN_ID"],
                       github_run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", "1"), started_at=now().isoformat())))
            handoff = archive(moi, scans, date)
            preview.validate_handoff(handoff, date)
            ready_id = moi.upload(ready_name, pack(handoff))
            receipt["reused_existing_ready"] = False
        receipt.update(status="archive_verified", archive_batch_id=handoff["archive_batch_id"],
                       handoff_file_id=ready_id, archive_status=handoff["archive_receipt"]["archive_status"],
                       readback_verified=True, files_verified=True,
                       all_sources_available=all(r["scan_status"] in {"clean", "vulnerabilities_found", "scan_partial"} for r in handoff["scan_runs"]),
                       scan_coverage_complete=all(r["scan_status"] in {"clean", "vulnerabilities_found"} for r in handoff["scan_runs"]),
                       completed_at=now().isoformat())
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                out.write("report_date=" + date + "\nhandoff_file_id=" + ready_id + "\n")
        exit_code = 0
    except (Error, exchange.ScanError) as exc:
        receipt.update(status="blocked", error_code=str(exc))
    except Exception:
        receipt.update(status="blocked", error_code="unexpected_error_details_withheld")
    path = Path("out/moi-cloud-prepare-receipt.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pack(receipt))
    print("MOI cloud preparation: " + receipt["status"]
          + (" (" + receipt["error_code"] + ")" if receipt.get("error_code") else ""))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Cloud preparation\n\nStatus: `" + receipt["status"] + "`"
                          + ("\nError code: `" + receipt["error_code"] + "`" if receipt.get("error_code") else "")
                          + "\n\nWeCom sending: disabled.\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
