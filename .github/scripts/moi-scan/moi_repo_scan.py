#!/usr/bin/env python3
"""Publish a repository's OSV report to MOI; read manifests for daily aggregation."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = "https://api.moi.matrixorigin.cn/v5"
WORKSPACE = "fd3f15fe-3ac3-1c8c-5020-dffec978a0cb"
VOLUME = 130001
LOCAL = dt.timezone(dt.timedelta(hours=8))
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
CONFIG = {
    "matrixone": ("CUIShaoXin/matrixone", "main", ".github/workflows/matrixone-osv-feishu.yml"),
    "taas": ("matrixorigin/taas", "main", ".github/workflows/daily-osv-scan.yml"),
    "matrixflow": ("matrixorigin/matrixflow", "dev", ".github/workflows/daily-osv-scan.yml"),
}
GOOD = {"clean", "vulnerabilities_found", "scan_partial"}
STATUSES = GOOD | {"scan_failed"}
LIMIT = 128 * 1024 * 1024


class ScanError(Exception):
    """Public error messages are static codes without response bodies."""


def require(condition, code):
    if not condition:
        raise ScanError(code)


def now():
    return dt.datetime.now(LOCAL)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pack(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def instant(value):
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(stamp.tzinfo is not None, "timestamp_timezone_required")
        return stamp
    except (TypeError, ValueError, AttributeError):
        raise ScanError("invalid_scan_timestamp") from None


def data(response):
    code = response.get("code") if isinstance(response, dict) else None
    require(code == "OK" or type(code) is int and code in (0, 200), "moi_api_rejected")
    return response.get("data")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MOI:
    def __init__(self, key):
        require(bool(key), "missing_moi_api_key")
        self.key = key
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, payload=None, binary=False, timeout=60, multipart=None):
        require(path.startswith("/") and "://" not in path, "invalid_moi_path")
        headers = {"X-API-Key": self.key, "X-Workspace-ID": WORKSPACE}
        raw = None
        if multipart is not None:
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
            request = urllib.request.Request(ROOT + path, raw, headers)
            with self.opener.open(request, timeout=timeout) as response:
                body = response.read(LIMIT + 1)
                require(len(body) <= LIMIT, "moi_response_too_large")
                return body if binary else json.loads(body)
        except urllib.error.HTTPError as exc:
            raise ScanError("moi_http_" + str(exc.code)) from None
        except (OSError, ValueError):
            raise ScanError("moi_transport_or_json_error") from None

    def get(self, path, **params):
        return self.request(path + ("?" + urllib.parse.urlencode(params) if params else ""))

    def file(self, file_id):
        require(isinstance(file_id, str) and bool(re.fullmatch(UUID, file_id)), "invalid_file_id")
        return self.request("/catalog/file/download", {"file_id": file_id}, binary=True)

    def named_files(self, name, fuzzy=False):
        listing = data(self.request("/catalog/file/list", {"filters": [
            {"name": "volume_id", "values": [str(VOLUME)]},
            {"name": "file_name", "values": [name], "fuzzy": fuzzy}], "page": 1, "page_size": 100}))
        require(type(listing.get("total")) is int and listing["total"] <= 100,
                "archive_listing_truncated")
        matches = [x for x in listing.get("list", [])
                   if (name in x.get("name", "") if fuzzy else x.get("name") == name)]
        for entry in matches:
            require(str(entry.get("volume_id")) == str(VOLUME), "wrong_archive_volume")
            require(bool(re.fullmatch(UUID, entry.get("id", ""))), "invalid_file_id")
        return matches

    def named_file(self, name):
        matches = self.named_files(name)
        require(len(matches) <= 1, "ambiguous_archive_filename")
        return matches[0]["id"] if matches else None

    def upload(self, name, raw):
        file_id = self.named_file(name)
        if not file_id:
            file_id = data(self.request("/catalog/file/upload", multipart=(name, raw)))["file_id"]
            require(bool(re.fullmatch(UUID, file_id)), "invalid_uploaded_file_id")
            data(self.request("/catalog/file/create", {"volume_id": VOLUME, "file_ids": [file_id]}))
            require(self.named_file(name) == file_id, "uploaded_file_mount_not_verified")
        downloaded = self.file(file_id)
        require(len(downloaded) == len(raw) and sha(downloaded) == sha(raw),
                "uploaded_file_readback_mismatch")
        return file_id


def raw_counts(raw):
    try:
        report = json.loads(raw)
        require(isinstance(report, dict) and isinstance(report.get("results"), list)
                and not report.get("scan_error"), "invalid_osv_report")
        packages, identifiers, hits = set(), set(), 0
        for result in report["results"]:
            for item in result.get("packages", []):
                vulnerabilities = item.get("vulnerabilities", [])
                if vulnerabilities:
                    packages.add(item["package"]["name"])
                for vuln in vulnerabilities:
                    hits += 1
                    identifier = next((x for x in vuln.get("aliases", []) if x.startswith("CVE-")),
                                      vuln.get("id"))
                    require(bool(identifier), "missing_vulnerability_identifier")
                    identifiers.add(identifier)
        return hits, len(identifiers), len(packages)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ScanError("invalid_osv_report") from None


def summarize(raw, stderr, exit_code):
    counts, error = (None, None, None), ""
    try:
        require(exit_code in (0, 1), "scanner_exit_failed")
        require(raw is not None and stderr is not None, "missing_raw_scan_files")
        counts = raw_counts(raw)
        partial = bool(re.search(rb"Error during extraction:|failed resolution for", stderr))
        status = "scan_partial" if partial else ("vulnerabilities_found" if counts[0] else "clean")
    except ScanError as exc:
        status, error = "scan_failed", str(exc)
    return dict(status=status, hits=counts[0], unique_ids=counts[1], packages=counts[2],
                error=error, scanner_exit_code=exit_code)


def prefix(name, date):
    return "repo-scan-v1-" + name + "-" + date.replace("-", "") + "-"


def manifest_name(envelope):
    run = envelope["scan"]["run"]
    return prefix(envelope["name"], envelope["report_date"]) + str(run["id"]) + "-" + str(run["run_attempt"]) + ".json"


def validate(envelope, name, date, current):
    require(envelope.get("schema_version") == 1, "scan_manifest_schema_mismatch")
    require(envelope.get("workspace_id") == WORKSPACE and envelope.get("volume_id") == VOLUME,
            "scan_manifest_target_mismatch")
    require(envelope.get("name") == name and envelope.get("report_date") == date,
            "scan_manifest_repository_or_date_mismatch")
    scan = envelope["scan"]
    execution, branch, workflow = CONFIG[name]
    require(scan.get("name") == name and scan.get("repository") == "matrixorigin/" + name
            and scan.get("execution_repository") == execution and scan.get("branch") == branch,
            "scan_source_mismatch")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", scan.get("commit", ""))), "invalid_scanned_commit")
    require(scan.get("status") in STATUSES and scan.get("scanner_version") == "2.7.0",
            "invalid_scan_status_or_version")
    run = scan["run"]
    require(type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
            "invalid_source_run_identity")
    require(run.get("path") == workflow and run.get("head_branch") == branch
            and run.get("event") in {"schedule", "workflow_dispatch"}, "unexpected_scan_workflow")
    require(run.get("html_url") == "https://github.com/" + execution + "/actions/runs/" + str(run["id"]),
            "source_run_url_mismatch")
    created, started, finished = (instant(run["created_at"]), instant(scan["started_at"]),
                                  instant(scan["finished_at"]))
    floor = dt.datetime.combine(dt.date.fromisoformat(date), dt.time(7, 30), LOCAL)
    require(floor <= created <= started <= finished <= current
            and finished.astimezone(LOCAL).date().isoformat() == date, "stale_or_future_scan")
    counters = tuple(scan.get(k) for k in ("hits", "unique_ids", "packages"))
    if scan["status"] in GOOD:
        require(all(type(v) is int and v >= 0 for v in counters)
                and counters[1] <= counters[0] and counters[2] <= counters[0],
                "invalid_scan_counters")
        require(scan.get("scanner_exit_code") in (0, 1) and not scan.get("error"),
                "scanner_did_not_complete")
        require((scan["status"] != "clean" or counters[0] == 0)
                and (scan["status"] != "vulnerabilities_found" or counters[0] > 0),
                "scan_status_count_mismatch")
        require(set(envelope["files"]) == {"raw", "stderr"}, "missing_raw_scan_files")
    else:
        require(counters == (None, None, None) and bool(scan.get("error")), "failed_counts_must_be_null")
    require(set(envelope["files"]) <= {"raw", "stderr"}, "unexpected_scan_file")
    for entry in envelope["files"].values():
        require(bool(re.fullmatch(UUID, entry.get("file_id", "")))
                and bool(re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")))
                and type(entry.get("size")) is int and 0 <= entry["size"] <= LIMIT, "invalid_scan_file_evidence")
    return scan


def publish(moi, name, date, scan, files, current):
    envelope = dict(schema_version=1, workspace_id=WORKSPACE, volume_id=VOLUME,
                    name=name, report_date=date, scan=scan, files={})
    stem = manifest_name(envelope)[:-5]
    for kind, raw in files.items():
        if raw is not None:
            filename = stem + "-" + sha(raw) + ("-osv.json" if kind == "raw" else "-stderr.txt")
            file_id = moi.upload(filename, raw)
            envelope["files"][kind] = dict(file_id=file_id, sha256=sha(raw), size=len(raw))
    validate(envelope, name, date, current)
    # Publish the manifest last. A failed or uncertain upload cannot expose a ready source.
    file_id = moi.upload(manifest_name(envelope), pack(envelope))
    return dict(status="scan_uploaded", repository=scan["repository"], report_date=date,
                scan_status=scan["status"], source_run_id=scan["run"]["id"],
                source_run_attempt=scan["run"]["run_attempt"], manifest_file_id=file_id,
                readback_verified=True, sent=False)


def read_scan(moi, name, date, current):
    entries = moi.named_files(prefix(name, date), fuzzy=True)
    pattern = re.compile(re.escape(prefix(name, date)) + r"\d+-\d+\.json")
    entries = [e for e in entries if pattern.fullmatch(e["name"])]
    if not entries:
        return dict(name=name, repository="matrixorigin/" + name, branch=CONFIG[name][1],
                    commit="", status="pending", hits=None, unique_ids=None, packages=None,
                    error="no_current_day_upload", run=None, raw=None, stderr=None)
    candidates = []
    for entry in entries:
        envelope = json.loads(moi.file(entry["id"]))
        scan = validate(envelope, name, date, current)
        require(manifest_name(envelope) == entry["name"], "scan_manifest_filename_mismatch")
        candidates.append((instant(scan["run"]["created_at"]), scan["run"]["id"],
                           scan["run"]["run_attempt"], envelope, entry["id"]))
    _, _, _, envelope, file_id = max(candidates, key=lambda row: row[:3])
    scan = dict(envelope["scan"])
    for kind in ("raw", "stderr"):
        info = envelope["files"].get(kind)
        raw = moi.file(info["file_id"]) if info else None
        if info:
            require(len(raw) == info["size"] and sha(raw) == info["sha256"], "source_file_readback_mismatch")
        scan[kind] = raw
    if scan["status"] in GOOD:
        require(raw_counts(scan["raw"]) == tuple(scan[k] for k in ("hits", "unique_ids", "packages")),
                "raw_summary_count_mismatch")
        result = summarize(scan["raw"], scan["stderr"], scan["scanner_exit_code"])
        require(result["status"] == scan["status"], "scan_status_evidence_mismatch")
    scan["manifest_file_id"] = file_id
    return scan


def source_run(name, key):
    execution, branch, workflow = CONFIG[name]
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == execution
            and os.environ.get("GITHUB_REF") == "refs/heads/" + branch, "unexpected_runner_or_repository")
    require(os.environ.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch"}, "unexpected_scan_event")
    require(bool(key), "missing_repository_token")
    run_id = os.environ["GITHUB_RUN_ID"]
    require(run_id.isdigit(), "invalid_source_run_identity")
    request = urllib.request.Request("https://api.github.com/repos/" + execution + "/actions/runs/" + run_id,
        headers={"Authorization": "Bearer " + key, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "matrix-moi-self-scan"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "github_response_too_large")
            run = json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise ScanError("github_http_" + str(exc.code)) from None
    except (OSError, ValueError):
        raise ScanError("github_transport_or_json_error") from None
    require(run.get("id") == int(run_id)
            and run.get("run_attempt") == int(os.environ["GITHUB_RUN_ATTEMPT"])
            and run.get("path") == workflow and run.get("head_branch") == branch,
            "source_run_identity_mismatch")
    return {k: run[k] for k in ("id", "path", "head_branch", "run_attempt", "created_at", "event", "html_url")}


def main():
    os.umask(0o077)
    receipt = dict(status="blocked", sent=False)
    code = 1
    try:
        execution = os.environ.get("GITHUB_REPOSITORY")
        names = [n for n, c in CONFIG.items() if c[0] == execution]
        require(len(names) == 1, "unexpected_execution_repository")
        name = names[0]
        run = source_run(name, os.environ.get("GITHUB_TOKEN", ""))
        current = now()
        date = current.date().isoformat()
        raw_path, stderr_path = Path("osv-results.json"), Path("osv-scanner.stderr")
        raw = raw_path.read_bytes() if raw_path.exists() else None
        stderr = stderr_path.read_bytes() if stderr_path.exists() else None
        require(all(value is None or len(value) <= LIMIT for value in (raw, stderr)), "scan_report_too_large")
        scan = dict(name=name, repository="matrixorigin/" + name, execution_repository=execution,
                    branch=CONFIG[name][1], commit=os.environ.get("COMMIT_SHA", ""),
                    run=run, started_at=os.environ["SCAN_STARTED_AT"], finished_at=current.isoformat(),
                    scanner_version="2.7.0", coverage="OSV dependency scan; no source static analysis",
                    **summarize(raw, stderr, int(os.environ.get("SCAN_EXIT_CODE") or "2")))
        if scan["status"] == "scan_partial":
            scan["coverage"] += "; dependency extraction incomplete"
        moi = MOI(os.environ.get("MOI_API_KEY", ""))
        receipt = publish(moi, name, date, scan, dict(raw=raw, stderr=stderr), current)
        code = 0
    except ScanError as exc:
        receipt["error_code"] = str(exc)
    except Exception:
        receipt["error_code"] = "unexpected_upload_error_details_withheld"
    path = Path("out/moi-scan-upload-receipt.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pack(receipt))
    print("MOI repository upload: " + receipt["status"]
          + (" (" + receipt["error_code"] + ")" if receipt.get("error_code") else ""))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
            out.write("\nMOI upload: " + receipt["status"] + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())

