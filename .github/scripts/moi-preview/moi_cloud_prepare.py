#!/usr/bin/env python3
"""Collect current scans, scan a verified manifest snapshot, archive, then hand off.

Private data stays on the ephemeral runner and in the fixed MOI workspace.
Only a sanitized receipt is suitable for a public GitHub artifact.
"""
import base64
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

import archive_schema as schema
import moi_archive_preview as preview

LOCAL = dt.timezone(dt.timedelta(hours=8))
WORKSPACE = preview.WORKSPACE
VOLUME = 130001
WORKFLOW = "b7c59a89-7755-5611-8cfb-994f6cebc8d6"
PREFIX = "/workflow/v2/workflow-apps/" + WORKFLOW
CONFIG = {
    "matrixone": ("CUIShaoXin/matrixone", "main", ".github/workflows/matrixone-osv-feishu.yml", "scan-and-notify"),
    "taas": ("matrixorigin/taas", "main", ".github/workflows/daily-osv-scan.yml", "scan"),
    "matrixflow": ("matrixorigin/matrixflow", "dev", None, None),
}
MANIFEST = re.compile(r"(^|/)(go\.(mod|sum|work)|package(-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|[^/]*requirements[^/]*\.(txt|in|lock)|pyproject\.toml|poetry\.lock|Pipfile(\.lock)?|uv\.lock|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|packages\.lock\.json|packages\.config|composer\.(json|lock)|Gemfile(\.lock)?|Cargo\.(toml|lock)|conan\.lock|mix\.lock|pubspec\.(yaml|lock)|osv-scanner\.toml|\.gitignore|.*\.(spdx\.json|cdx\.json))$", re.I)
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


class MOI(preview.Client):
    def request(self, path, payload=None, binary=False, timeout=60, multipart=None):
        require(path.startswith("/") and "://" not in path, "invalid_moi_path")
        headers = {"X-API-Key": self.key, "X-Workspace-ID": WORKSPACE}
        raw = None
        if multipart:
            name, body = multipart
            require(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,240}", name)), "invalid_upload_name")
            boundary = "moi" + uuid.uuid4().hex
            headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
            raw = (("--" + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="'
                    + name + '"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
                   + body + ("\r\n--" + boundary + "--\r\n").encode())
        elif payload is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(payload, ensure_ascii=False).encode()
        try:
            request = urllib.request.Request(preview.ROOT + path, raw, headers)
            with self.opener.open(request, timeout=timeout) as response:
                body = response.read(128 * 1024 * 1024 + 1)
                require(len(body) <= 128 * 1024 * 1024, "moi_response_too_large")
                return body if binary else json.loads(body)
        except urllib.error.HTTPError as exc:
            raise Error("moi_http_" + str(exc.code)) from None
        except (OSError, ValueError):
            raise Error("moi_transport_or_json_error") from None

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

    def named_file(self, name):
        listing = data(self.request("/catalog/file/list", {"filters": [
            {"name": "volume_id", "values": [str(VOLUME)]},
            {"name": "file_name", "values": [name], "fuzzy": False}], "page": 1, "page_size": 100}))
        matches = [x for x in listing.get("list", []) if x.get("name") == name]
        require(listing.get("total", 0) <= 100 and len(matches) <= 1, "ambiguous_archive_filename")
        if matches:
            require(str(matches[0]["volume_id"]) == str(VOLUME), "wrong_archive_volume")
            return matches[0]["id"]
        return None

    def upload(self, name, raw):
        file_id = self.named_file(name)
        if not file_id:
            file_id = data(self.request("/catalog/file/upload", multipart=(name, raw)))["file_id"]
            require(bool(re.fullmatch(preview.UUID, file_id)), "invalid_uploaded_file_id")
            # No write retry: an ambiguous response must be inspected, not blindly repeated.
            data(self.request("/catalog/file/create", {"volume_id": VOLUME, "file_ids": [file_id]}))
            require(self.named_file(name) == file_id, "uploaded_file_mount_not_verified")
        downloaded = self.file(file_id)
        require(len(downloaded) == len(raw) and sha(downloaded) == sha(raw), "uploaded_file_readback_mismatch")
        return file_id


class GitHub:
    def __init__(self, key):
        self.key = key
        self.opener = urllib.request.build_opener(preview.NoRedirect())

    def read(self, path, binary=False):
        require(path.startswith("/repos/") and "://" not in path, "invalid_github_path")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "matrix-security-archive"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        request = urllib.request.Request("https://api.github.com" + path, headers=headers)
        try:
            response = self.opener.open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and binary:
                url = urllib.parse.urlsplit(exc.headers.get("Location", ""))
                allowed = url.hostname and any(url.hostname.endswith("." + host) for host in
                    ("blob.core.windows.net", "githubusercontent.com"))
                require(url.scheme == "https" and allowed and not url.username and not url.password,
                        "untrusted_github_download_redirect")
                # The signed storage URL is never logged; no GitHub credential follows it.
                response = self.opener.open(urllib.request.Request(url.geturl()), timeout=90)
            else:
                raise Error("github_http_" + str(exc.code)) from None
        except OSError:
            raise Error("github_transport_error") from None
        with response:
            raw = response.read(64 * 1024 * 1024 + 1)
        require(len(raw) <= 64 * 1024 * 1024, "github_response_too_large")
        return raw if binary else json.loads(raw)


def fresh_run(runs, config, date, current):
    repo, branch, workflow, _ = config
    floor = dt.datetime.combine(dt.date.fromisoformat(date), dt.time(7, 30), LOCAL)
    candidates = [r for r in runs if r.get("path") == workflow and r.get("head_branch") == branch]
    if not candidates:
        return None
    run = max(candidates, key=lambda x: (x["created_at"], x["id"]))
    created = dt.datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    return run if floor <= created <= current and created.astimezone(LOCAL).date().isoformat() == date else None


def scan_summary(name, logs):
    if name == "taas":
        values = re.findall(r"^\d{4}-\d\d-\d\dT\S+ SECURITY_SCAN_SUMMARY=(\{[^\n]+\})\r?$", logs, re.M)
        require(bool(values), "missing_scan_summary")
        value = json.loads(values[-1])
        require(value.get("repository") == "matrixorigin/taas", "scan_repository_mismatch")
        return value
    fields = {}
    for match in re.finditer(r"^\d{4}-\d\d-\d\dT\S+\s+(COMMIT_SHA|SCAN_STATUS|VULNERABILITY_COUNT|UNIQUE_VULNERABILITY_COUNT|PACKAGE_COUNT):\s*(\S+)\s*$", logs, re.M):
        fields[match[1]] = match[2]
    require(set(fields) == {"COMMIT_SHA", "SCAN_STATUS", "VULNERABILITY_COUNT", "UNIQUE_VULNERABILITY_COUNT", "PACKAGE_COUNT"}, "missing_scan_summary")
    return dict(commit=fields["COMMIT_SHA"], status=fields["SCAN_STATUS"],
                hits=int(fields["VULNERABILITY_COUNT"]), unique_ids=int(fields["UNIQUE_VULNERABILITY_COUNT"]),
                packages=int(fields["PACKAGE_COUNT"]))


def raw_counts(raw):
    report = json.loads(raw)
    require(isinstance(report, dict) and isinstance(report.get("results"), list)
            and not report.get("scan_error"), "invalid_osv_report")
    packages, identifiers, hits = set(), set(), 0
    for result in report["results"]:
        for package in result.get("packages", []):
            if package.get("package", {}).get("name"):
                packages.add(package["package"]["name"])
            for vuln in package.get("vulnerabilities", []):
                hits += 1
                identifier = next((x for x in vuln.get("aliases", []) if x.startswith("CVE-")), vuln.get("id"))
                require(bool(identifier), "missing_vulnerability_identifier")
                identifiers.add(identifier)
    return hits, len(identifiers), len(packages)


def artifact_files(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sum(x.file_size for x in archive.infolist()) <= 128 * 1024 * 1024,
                "artifact_expanded_size_exceeded")
        result = {}
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts, "unsafe_artifact_path")
            require(path.name in {"osv-results.json", "osv-scanner.stderr", "scan-summary.json"}
                    and path.name not in result, "unexpected_artifact_file")
            result[path.name] = archive.read(entry)
    require("osv-results.json" in result and "osv-scanner.stderr" in result, "missing_raw_scan_artifact")
    return result


def failed(name, error, status="unavailable", run=None):
    return dict(name=name, repository="matrixorigin/" + name, branch=CONFIG[name][1],
                status=status, error=error, hits=None, unique_ids=None, packages=None,
                commit="", run=run_evidence(run), raw=None, stderr=None)


def run_evidence(run):
    return {k: run[k] for k in ("id", "path", "head_branch", "run_number", "run_attempt", "status",
            "conclusion", "created_at", "updated_at", "event", "html_url") if k in run} if run else None


def collect(gh, name, date, current):
    config = CONFIG[name]
    repo, branch, workflow, job_name = config
    path = "/repos/" + repo
    run = None
    try:
        run = fresh_run(gh.read(path + "/actions/runs?per_page=100")["workflow_runs"], config, date, current)
        if not run:
            return failed(name, "no_current_day_run", "pending")
        if run["status"] != "completed":
            return failed(name, "current_run_not_completed", "pending", run)
        jobs = gh.read(path + "/actions/runs/" + str(run["id"]) + "/jobs?filter=latest&per_page=100")
        selected = [j for j in jobs["jobs"] if j["name"] == job_name]
        require(len(selected) == 1, "ambiguous_scan_job")
        job = selected[0]
        require(job.get("run_attempt") == run["run_attempt"] and job.get("run_id") == run["id"], "scan_attempt_mismatch")
        require(any(s["name"] == "Summarize scan" and s["conclusion"] == "success" for s in job["steps"]), "scan_summary_step_failed")
        summary = scan_summary(name, gh.read(path + "/actions/jobs/" + str(job["id"]) + "/logs", binary=True).decode())
        require(bool(re.fullmatch(r"[0-9a-f]{40}", summary.get("commit", ""))), "invalid_scanned_commit")
        require(summary.get("status") in {"clean", "vulnerabilities_found", "scan_partial"}, "scan_did_not_complete")
        if name == "taas":
            require(summary.get("scanner_exit_code") in (0, 1) and not summary.get("error"), "scanner_exit_failed")
        artifacts = gh.read(path + "/actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")
        require(artifacts.get("total_count", 0) <= 100, "artifact_list_truncated")
        expected = ("matrixone-osv-" + str(run["run_number"]) if name == "matrixone" else
                    "osv-scan-" + str(run["run_number"]) + "-" + str(run["run_attempt"]))
        matches = [a for a in artifacts["artifacts"] if a["name"] == expected and not a["expired"]
                   and a["created_at"] >= job["started_at"]]
        require(len(matches) == 1, "artifact_attempt_not_verified")
        artifact = matches[0]
        files = artifact_files(gh.read(path + "/actions/artifacts/" + str(artifact["id"]) + "/zip", binary=True))
        raw, stderr = files["osv-results.json"], files["osv-scanner.stderr"]
        counts = raw_counts(raw)
        require(counts == tuple(summary[k] for k in ("hits", "unique_ids", "packages")), "raw_summary_count_mismatch")
        if name == "taas":
            require(json.loads(files["scan-summary.json"]) == summary, "artifact_summary_mismatch")
        partial = bool(re.search(rb"Error during extraction:|failed resolution for", stderr)) or summary["status"] == "scan_partial"
        return dict(name=name, repository="matrixorigin/" + name, branch=branch,
                    commit=summary["commit"], status="scan_partial" if partial else summary["status"],
                    hits=counts[0], unique_ids=counts[1], packages=counts[2], error="", run=run_evidence(run),
                    job_id=job["id"], artifact_id=artifact["id"], raw=raw, stderr=stderr,
                    started_at=job["started_at"], finished_at=job.get("completed_at", ""),
                    coverage="OSV dependency scan; " + ("dependency extraction incomplete" if partial else "source workflow report verified"))
    except Error as exc:
        return failed(name, str(exc), "scan_failed" if run and run["status"] == "completed" else "unavailable", run)
    except (KeyError, ValueError, OSError, zipfile.BadZipFile):
        return failed(name, "invalid_scan_evidence", "scan_failed", run)


def safe_manifest(entry):
    path = PurePosixPath(entry["path"])
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in str(path)
            and entry.get("mode") != "120000", "unsafe_manifest_path")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", entry.get("sha", ""))), "invalid_manifest_blob_sha")


def snapshot(gh, directory):
    prefix = "/repos/matrixorigin/matrixflow"
    revision = gh.read(prefix + "/commits/dev")
    commit, tree_sha = revision["sha"], revision["commit"]["tree"]["sha"]
    require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "invalid_matrixflow_commit")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", tree_sha)), "invalid_matrixflow_tree")
    root = gh.read(prefix + "/git/trees/" + tree_sha)
    require(root.get("truncated") is False, "truncated_manifest_root")
    entries = [e for e in root["tree"] if e["type"] != "tree"]

    def subtree(entry):
        value = gh.read(prefix + "/git/trees/" + entry["sha"] + "?recursive=1")
        require(value.get("truncated") is False, "truncated_manifest_subtree")
        return [dict(e, path=entry["path"] + "/" + e["path"]) for e in value["tree"]]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(subtree, [e for e in root["tree"] if e["type"] == "tree"]):
            entries.extend(result)
    selected = [e for e in entries if e["type"] == "blob" and MANIFEST.search(e["path"])]
    require(0 < len(selected) <= 2000, "invalid_manifest_count")
    require(len({e["path"] for e in selected}) == len(selected), "duplicate_manifest_paths")
    for entry in selected:
        safe_manifest(entry)

    def download(entry):
        require(0 <= entry["size"] <= 8 * 1024 * 1024, "manifest_too_large")
        blob = gh.read(prefix + "/git/blobs/" + entry["sha"])
        require(blob.get("encoding") == "base64", "invalid_git_blob_encoding")
        raw = base64.b64decode(blob["content"])
        actual = hashlib.sha1(("blob " + str(len(raw)) + "\0").encode() + raw).hexdigest()
        require(actual == entry["sha"] and len(raw) == entry["size"], "git_blob_integrity_mismatch")
        path = directory.joinpath(*PurePosixPath(entry["path"]).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(download, selected))
    manifest = dict(repository="matrixorigin/matrixflow", branch="dev", commit=commit,
                    tree_sha=tree_sha, complete=True, tree_truncated=False,
                    files=[{k: e[k] for k in ("path", "sha", "size")} for e in selected])
    (directory / "SNAPSHOT_MANIFEST.json").write_bytes(pack(manifest))
    return manifest


def scan_matrixflow(gh):
    try:
        with tempfile.TemporaryDirectory(prefix="matrix-manifests-") as temp:
            root = Path(temp)
            manifest = snapshot(gh, root)
            started = now().isoformat()
            # Pass no API tokens to the scanner or dependency resolvers.
            env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "SSL_CERT_FILE") if k in os.environ}
            proc = subprocess.run([os.environ.get("OSV_SCANNER", "/tmp/matrix-osv-scanner"),
                "scan", "source", "--recursive", "--no-ignore", "--no-call-analysis=go",
                "--no-call-analysis=rust", "--format=json", str(root)], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1200, check=False)
            require(proc.returncode in (0, 1), "matrixflow_scanner_failed")
            counts = raw_counts(proc.stdout)
            partial = bool(re.search(rb"Error during extraction:|failed resolution for", proc.stderr))
            return dict(name="matrixflow", repository="matrixorigin/matrixflow", branch="dev",
                        commit=manifest["commit"], status="scan_partial" if partial else
                        ("vulnerabilities_found" if counts[0] else "clean"), hits=counts[0],
                        unique_ids=counts[1], packages=counts[2], error="", run=None,
                        started_at=started, finished_at=now().isoformat(), raw=proc.stdout,
                        stderr=proc.stderr, snapshot_verified=True, manifest_count=len(manifest["files"]),
                        manifest_sha256=sha(pack(manifest)), scanner_version="2.7.0",
                        coverage="Verified dependency manifests and lockfiles only; not source static analysis. "
                        + ("Incomplete transitive dependency resolution." if partial else ""))
    except subprocess.TimeoutExpired:
        return failed("matrixflow", "scanner_timeout", "scan_failed")
    except Error as exc:
        return failed("matrixflow", str(exc))
    except (ValueError, KeyError, OSError):
        return failed("matrixflow", "snapshot_or_scanner_error", "scan_failed")


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
            execution_source="github_actions:" + (CONFIG[name][0] if name != "matrixflow" else os.environ["GITHUB_REPOSITORY"]),
            source_run_id=str(run.get("id", os.environ["GITHUB_RUN_ID"])),
            source_run_attempt=str(run.get("run_attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "1"))),
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
            key = os.environ.get("SCAN_GITHUB_TOKEN", "").strip()
            require(bool(key), "private_repository_token_required")
            repository_key = os.environ.get("GITHUB_TOKEN", "").strip()
            require(bool(repository_key), "execution_repository_token_required")
            if os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true":
                require(now().time() < dt.time(9, 50), "daily_preparation_window_missed")
            gh = GitHub(key)
            source_clients = {"matrixone": GitHub(repository_key), "taas": gh}
            # Before scanning or writing, verify the two private-repository read scopes.
            for repo in ("matrixorigin/taas", "matrixorigin/matrixflow"):
                access = gh.read("/repos/" + repo)
                require(access.get("full_name", "").lower() == repo.lower(), "private_repository_access_mismatch")
            lock_name = "cloud-preparation-lock-" + date.replace("-", "") + ".json"
            require(moi.named_file(lock_name) is None, "existing_preparation_requires_recovery")
            moi.upload(lock_name, pack(dict(report_date=date, github_run_id=os.environ["GITHUB_RUN_ID"],
                       github_run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", "1"), started_at=now().isoformat())))
            scans = {name: collect(source_clients[name], name, date, now()) for name in ("matrixone", "taas")}
            scans["matrixflow"] = scan_matrixflow(gh)
            deadline = now().replace(hour=9, minute=50, second=0, microsecond=0)
            while os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true" and now() < deadline and any(scans[n]["status"] == "pending" for n in ("matrixone", "taas")):
                time.sleep(min(60, max(1, (deadline - now()).total_seconds())))
                for name in ("matrixone", "taas"):
                    if scans[name]["status"] == "pending":
                        scans[name] = collect(source_clients[name], name, date, now())
            if os.environ.get("WAIT_FOR_CLOUD_RUNS") == "true":
                require(now().time() < dt.time(9, 55), "daily_archival_window_missed")
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
    except Error as exc:
        receipt.update(status="blocked", error_code=str(exc))
    except Exception:
        receipt.update(status="blocked", error_code="unexpected_error_details_withheld")
    path = Path("out/moi-cloud-prepare-receipt.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pack(receipt))
    print("MOI cloud preparation: " + receipt["status"])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Cloud preparation\n\nStatus: `" + receipt["status"] + "`\n\nWeCom sending: disabled.\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
