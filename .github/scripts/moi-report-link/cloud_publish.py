from __future__ import annotations
"""Publish verified report bytes using the existing MinIO connector.

Secrets are resolved in memory through the existing workspace API. Nothing in
this module changes bucket access policies or prints credential material.
"""

import datetime as dt
import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request

CONNECTOR_ID = "468787000051"
EXPECTED_ENDPOINT = "https://shanghai.idc.matrixorigin.cn:30002"
EXPECTED_BUCKET = "daily-security-report"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


class Objects:
    def __init__(self, config):
        self.endpoint = config["endpoint"].rstrip("/")
        self.bucket = config["bucket_name"]
        if self.endpoint != EXPECTED_ENDPOINT or self.bucket != EXPECTED_BUCKET:
            raise ValueError("unexpected_report_destination")
        self.region = config.get("region") or "us-east-1"
        self._access = config["access_key_id"]
        self._secret = config["access_key_secret"]
        self.host = urllib.parse.urlsplit(self.endpoint).netloc

    @classmethod
    def from_workspace(cls, api):
        result = api.request("/connectors/get", {"id": CONNECTOR_ID}, timeout=25)
        if result["http_status"] != 200:
            raise RuntimeError("minio_connector_unavailable")
        connector = api.data(result)
        connector = connector.get("connector", connector)
        config = connector["config"]
        config = json.loads(config) if isinstance(config, str) else config
        return cls(config.get("s3", config.get("s3_config", {})))

    def _path(self, key):
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError("unsafe_object_key")
        return urllib.parse.quote("/" + self.bucket + "/" + key, safe="/-_.~")

    def _signature(self, date, message):
        def hm(key, value):
            return hmac.new(key, value.encode(), hashlib.sha256).digest()

        key = hm(hm(hm(hm(("AWS4" + self._secret).encode(), date), self.region), "s3"), "aws4_request")
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    def call(self, method, key, raw=None, headers=None, response_limit=32 * 1024 * 1024):
        now = dt.datetime.now(dt.timezone.utc)
        stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        path = self._path(key)
        hdr = {"host": self.host, "x-amz-content-sha256": sha256(raw or b""), "x-amz-date": stamp}
        hdr.update({k.lower(): str(v).strip() for k, v in (headers or {}).items()})
        signed = ";".join(sorted(hdr))
        canonical_headers = "".join(k + ":" + hdr[k] + "\n" for k in sorted(hdr))
        canonical = "\n".join([method, path, "", canonical_headers, signed, hdr["x-amz-content-sha256"]])
        scope = date + "/" + self.region + "/s3/aws4_request"
        message = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, sha256(canonical.encode())])
        hdr["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + self._access + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + self._signature(date, message)
        request = urllib.request.Request(self.endpoint + path, data=raw, headers=hdr, method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
                body = response.read(response_limit + 1)
                if len(body) > response_limit:
                    raise ValueError("report_object_exceeds_limit")
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as error:
            raise RuntimeError("minio_http_" + str(error.code)) from None

    def publish(self, key, raw, content_type):
        digest = sha256(raw)
        self.call("PUT", key, raw, {
            "content-type": content_type,
            "content-disposition": "inline",
            "cache-control": "private, max-age=300",
            "x-amz-meta-sha256": digest,
        })
        status, headers, received = self.call("GET", key)
        if status != 200 or received != raw:
            raise ValueError("minio_report_readback_mismatch")
        return {"key": key, "bytes": len(raw), "sha256": digest, "readback_verified": True,
                "content_type": headers.get("Content-Type"), "content_disposition": headers.get("Content-Disposition")}

    def presign(self, key, seconds=604800, at=None):
        if not 1 <= seconds <= 604800:
            raise ValueError("invalid_link_lifetime")
        now = at or dt.datetime.now(dt.timezone.utc)
        stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        scope = date + "/" + self.region + "/s3/aws4_request"
        query = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": self._access + "/" + scope,
                 "X-Amz-Date": stamp, "X-Amz-Expires": str(seconds), "X-Amz-SignedHeaders": "host",
                 "response-content-type": "text/html; charset=utf-8", "response-content-disposition": "inline"}
        encoded = urllib.parse.urlencode(sorted(query.items()), quote_via=urllib.parse.quote, safe="-_.~")
        canonical = "\n".join(["GET", self._path(key), encoded, "host:" + self.host + "\n", "host", "UNSIGNED-PAYLOAD"])
        message = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, sha256(canonical.encode())])
        url = self.endpoint + self._path(key) + "?" + encoded + "&X-Amz-Signature=" + self._signature(date, message)
        return url, (now + dt.timedelta(seconds=seconds)).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_login_free(url, expected):
    # A new opener has neither login cookies nor an Authorization header.
    request = urllib.request.Request(url, headers={"Accept": "text/html"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
            raw = response.read(len(expected) + 1)
            if raw != expected or response.status != 200:
                raise ValueError("login_free_report_mismatch")
            if "text/html" not in response.headers.get("Content-Type", ""):
                raise ValueError("report_not_served_as_html")
            if response.headers.get("Content-Disposition", "").lower().startswith("attachment"):
                raise ValueError("report_forces_download")
            return {"http": response.status, "bytes": len(raw), "sha256": sha256(raw),
                    "content_type": response.headers.get("Content-Type"),
                    "content_disposition": response.headers.get("Content-Disposition"),
                    "cookies_used": False, "authorization_header_used": False, "redirects_followed": False}
    except urllib.error.HTTPError as error:
        raise RuntimeError("login_free_http_" + str(error.code)) from None
"""Existing Actions secrets -> fixed GitHub ZIP -> existing MinIO, no group send."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request


WORKSPACE = "fd3f15fe-3ac3-1c8c-5020-dffec978a0cb"
API_ROOT = "https://api.moi.matrixorigin.cn/v5"
LOCAL = dt.timezone(dt.timedelta(hours=8))

class Failure(Exception):
    pass

class API:
    def __init__(self, key):
        if not key:
            raise Failure("missing_moi_api_key")
        self.key = key
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, payload=None, method=None, timeout=35):
        if not path.startswith("/") or "://" in path:
            raise Failure("invalid_moi_route")
        raw = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(API_ROOT + path, data=raw, method=method, headers={
            "X-API-Key": self.key, "X-Workspace-ID": WORKSPACE,
            "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as response:
                answer = json.loads(response.read(16 * 1024 * 1024))
                if answer.get("code") not in ("OK", 0, 200):
                    raise Failure("moi_api_rejected")
                return {"http_status": response.status, "payload": answer}
        except urllib.error.HTTPError as exc:
            raise Failure("moi_http_" + str(exc.code)) from None

    @staticmethod
    def data(result):
        return result["payload"].get("data", result["payload"])

class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, repository, path, binary=False):
        req = urllib.request.Request("https://api.github.com/repos/" + repository + path,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                     "User-Agent": "Matrix-MOI-ZIP-Preparation", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            response = self.opener.open(req, timeout=40)
        except urllib.error.HTTPError as exc:
            if binary and exc.code in (301, 302, 303, 307, 308):
                url = urllib.parse.urlsplit(exc.headers.get("Location", ""))
                if url.scheme != "https" or url.hostname != "codeload.github.com" or url.username or url.password:
                    raise Failure("github_untrusted_archive_redirect") from None
                # Never forward GitHub Authorization to the archive endpoint.
                try:
                    response = self.opener.open(urllib.request.Request(url.geturl()), timeout=60)
                except urllib.error.HTTPError as error:
                    raise Failure("github_archive_http_" + str(error.code)) from None
            else:
                raise Failure("github_http_" + str(exc.code)) from None
        with response:
            limit = 1024 * 1024 * 1024 if binary else 2 * 1024 * 1024
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise Failure("github_response_size_limit")
        return raw if binary else json.loads(raw)

def prepare_archive(github, objects, repository, run_id, date):
    full_name = repository.owner + "/" + repository.name
    commit = github.get(full_name, "/branches/" + repository.branch)["commit"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Failure("github_commit_invalid")
    raw = github.get(full_name, "/zipball/" + commit, binary=True)
    with tempfile.TemporaryFile() as stream:
        stream.write(raw)
        proof = validate_zip(stream, commit)
    key = "snapshots/" + date.replace("-", "") + "/" + repository.name + "/" + repository.name + "-" + commit + "-gha-" + run_id + ".zip"
    objects.call("PUT", key, raw, {"content-type": "application/zip", "x-amz-meta-sha256": proof["sha256"]})
    http, _, readback = objects.call("GET", key, response_limit=len(raw))
    if http != 200 or sha256(readback) != proof["sha256"] or len(readback) != proof["bytes"]:
        raise Failure("minio_archive_readback_mismatch")
    proof.update(repository=full_name, branch=repository.branch, key=key, report_date=date,
                 acquisition_location="GitHub Actions cloud runner", download_method="fixed-commit GitHub repository archive API",
                 daily_cloud_download_verified=True, minio_readback_verified=True,
                 repository_code_executed=False, private_dependency_source_downloaded=False,
                 acquired_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    proof_raw = json.dumps(proof, ensure_ascii=False, indent=2).encode()
    objects.publish(key[:-4] + "-inventory.json", proof_raw, "application/json")
    return proof

def main():
    receipt = {"schema": "matrix_cloud_zip_preflight_v1", "sent": False, "status": "running", "repositories": {}}
    out = Path("out")
    out.mkdir(exist_ok=True)
    try:
        date = dt.datetime.now(LOCAL).date().isoformat()
        api = API(os.environ.get("MOI_API_KEY", ""))
        objects = Objects.from_workspace(api)
        receipt["minio_connector"] = "available"
        token = os.environ.get("SCAN_GITHUB_TOKEN", "")
        if not token:
            raise Failure("missing_scan_github_token")
        github = GitHub(token)
        run_id = os.environ.get("GITHUB_RUN_ID", "manual") + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        private = {}
        for repository in REPOSITORIES:
            try:
                private[repository.name] = prepare_archive(github, objects, repository, run_id, date)
                receipt["repositories"][repository.name] = {"archive": "verified", "minio_readback": "verified"}
            except Exception as exc:
                receipt["repositories"][repository.name] = {"status": "failed", "error": str(exc) if isinstance(exc, Failure) else type(exc).__name__}
        receipt["status"] = "passed" if len(private) == 3 else "failed"
        # Private manifests and signed links are never emitted as public Actions artifacts.
        objects.publish("receipts/" + date.replace("-", "") + "/gha-" + run_id + "/cloud-archives.json",
                        json.dumps(private, ensure_ascii=False).encode(), "application/json")
    except Exception as exc:
        receipt.update(status="failed", error=str(exc) if isinstance(exc, Failure) else type(exc).__name__)
    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    (out / "moi-cloud-zip-preflight-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return 0 if receipt["status"] == "passed" else 1


"""Component-first group preview. Facts come only from the accepted scan batch."""
import datetime as dt
import re

REPOSITORIES = ("matrixone", "taas", "matrixflow")

def component_excerpt(employee):
    paragraphs = re.split(r"\n\s*\n", employee.strip())
    rows = [p.strip() for p in paragraphs if re.match(r"^(?:\d+\.|[-•])\s", p)]
    if len(rows) == 1 and "\n- " in rows[0]:
        rows = rows[0].split("\n")
    return rows[:2]

def message(batch, employees, url, expires):
    rows = ["【依赖安全检查｜完整报告】", batch["date"] + " · 研发请优先评估以下组件，普通同事暂无需操作。", ""]
    for repo in REPOSITORIES:
        result = batch["results"][repo]
        excerpts = component_excerpt(employees[repo])
        if not excerpts:
            raise ValueError("component_summary_missing:" + repo)
        rows.append(repo + "｜" + ("dev" if repo == "matrixflow" else "main") + " / " + result["commit"][:8])
        for excerpt in excerpts:
            rows.append(re.sub(r"^(?:\d+\.|[-•])\s*", "• ", excerpt).replace("\n", " "))
        rows.append("")
    local = dt.datetime.fromisoformat(expires).astimezone(dt.timezone(dt.timedelta(hours=8)))
    rows.extend(["重点组件日报（免登录）：", url,
                 "链接有效期至 " + local.strftime("%Y-%m-%d %H:%M") + "（北京时间）。", "",
                 "公告命中不等于线上可利用。候选版本以报告中的发布核验状态为准，兼容性需研发验证。采用 OSV API 静态版本匹配，范围/动态及传递依赖仍有未解析项；无同口径历史基线，不统计新增/修复。各仓公告分别去重。"])
    text = "\n".join(rows) + "\n"
    if len(text.encode()) > 4096:
        raise ValueError("component_message_exceeds_4096_bytes")
    return text
"""Publish any independently accepted MOI batch; never sends a group message."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


REPOSITORIES = ("matrixone", "taas", "matrixflow")

def verify_batch(batch, files, today, historical=False):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", batch.get("date", "")):
        raise ValueError("report_date_invalid")
    if batch["date"] != today and not historical:
        raise ValueError("stale_report_batch")
    if batch.get("workspace") != "fd3f15fe-3ac3-1c8c-5020-dffec978a0cb" or batch.get("knowledge_base_id") != 80001:
        raise ValueError("report_workspace_mismatch")
    if not batch.get("three_repository_reports_accepted") or set(batch.get("results", {})) != set(REPOSITORIES):
        raise ValueError("incomplete_report_batch")
    for repo in REPOSITORIES:
        result = batch["results"][repo]
        if not re.fullmatch(r"[0-9a-f]{40}", result.get("commit", "")):
            raise ValueError("report_commit_invalid")
        if not result.get("independent_readback_verified") or not result.get("kb_marker_retrieved"):
            raise ValueError("report_source_unaccepted")
        for kind in ("employee", "details", "osv"):
            evidence, raw = result["artifacts"][kind], files[(repo, kind)]
            if len(raw) != evidence["bytes"] or sha256(raw) != evidence["sha256"]:
                raise ValueError("report_hash_mismatch:" + repo + ":" + kind)
        scan = json.loads(files[(repo, "osv")])
        facts = scan["facts"]
        if scan.get("status") != "declared_version_queries_completed" or scan.get("commit") != result["commit"]:
            raise ValueError("scan_commit_or_status_mismatch")
        if facts.get("report_date_shanghai") != batch["date"] or scan.get("execution_location") != "MOI cloud Python worker":
            raise ValueError("scan_date_or_location_mismatch")
        if not scan.get("manifest_integrity_verified") or not scan.get("source_commit_verified"):
            raise ValueError("scan_evidence_unverified")
        if scan.get("private_dependency_source_downloaded") or scan.get("repository_code_executed"):
            raise ValueError("scan_boundary_mismatch")
        for field in ("input_files", "queried_package_versions", "affected_component_names", "unique_advisory_alias_groups"):
            if facts[field] != result["counts"][field]:
                raise ValueError("report_count_mismatch:" + field)
    if not historical and not batch.get("daily_cloud_download_verified"):
        raise ValueError("daily_archive_acquisition_unverified")
    return True

def publish(api, batch, files, destination, node, historical=False):
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).date().isoformat()
    verify_batch(batch, files, today, historical)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for repo in REPOSITORIES:
        for kind in ("employee", "details", "osv"):
            extension = ".json" if kind == "osv" else ".md"
            (destination / (repo + "-fullzip-" + kind + extension)).write_bytes(files[(repo, kind)])
    accepted = destination / "acceptance.json"
    accepted.write_text(json.dumps(batch, ensure_ascii=False))
    report = destination / "matrix-security-complete.html"
    subprocess.run([node, str(Path(__file__).with_name("render_report.mjs")), "--render", str(accepted), str(destination), str(report)], check=True)
    raw = report.read_bytes()
    objects = Objects.from_workspace(api)
    key = "reports/" + batch["date"].replace("-", "") + "/" + sha256(raw)[:16] + "/matrix-security-complete.html"
    uploaded = objects.publish(key, raw, "text/html; charset=utf-8")
    url, expiry = objects.presign(key)
    verification = verify_login_free(url, raw)
    preview = message(batch, {repo:files[(repo, "employee")].decode() for repo in REPOSITORIES}, url, expiry)
    receipt = {"schema": "matrix_report_share_v1", "report_date": batch["date"], "source_acceptance_sha256": sha256(accepted.read_bytes()),
               "repositories": {repo:batch["results"][repo]["commit"] for repo in REPOSITORIES},
               "source_acceptance": batch, "published": uploaded, "url": url, "expires_at_utc": expiry,
               "login_free_verification": verification, "message_sha256": sha256(preview.encode()), "message_bytes": len(preview.encode()),
               "historical_batch": historical, "publication_location": os.environ.get("MATRIX_PUBLICATION_LOCATION", "operator session"),
               "published_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "sent": False,
               "daily_cloud_download_verified": batch.get("daily_cloud_download_verified", False),
               "daily_automation_ready": False, "bucket_policy_changed": False}
    for name, body in (("published-report-receipt.json", json.dumps(receipt, ensure_ascii=False, indent=2)), ("wecom-message-preview.txt", preview)):
        file = destination / name
        file.write_text(body + ("\n" if name.endswith(".json") else ""))
        file.chmod(0o600)
    receipt_key = key.rsplit("/",1)[0] + "/publication-receipt.json"
    objects.publish(receipt_key, json.dumps(receipt, ensure_ascii=False).encode(), "application/json")
    return receipt, preview

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--historical", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    import moi_api as api
    batch = json.loads(Path(args.acceptance).read_text())
    files = {(repo,kind):(Path(args.source)/(repo+"-fullzip-"+kind+(".json" if kind=="osv" else ".md"))).read_bytes() for repo in REPOSITORIES for kind in ("employee","details","osv")}
    result,_ = publish(api,batch,files,args.output,os.environ.get("MATRIX_NODE","node"),args.historical)
    print(json.dumps({"published": True, "login_free_verified": True, "message_bytes": result["message_bytes"], "report_date": result["report_date"], "sent":False}))


"""Download accepted reports from MOI and publish a browser-readable MinIO copy."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import uuid


class ReportAPI(API):
    def binary(self, path, payload=None, raw=None, content_type="application/json"):
        if raw is None and payload is not None:
            raw=json.dumps(payload).encode()
        req=urllib.request.Request(API_ROOT+path,data=raw,headers={
            "X-API-Key":self.key,"X-Workspace-ID":WORKSPACE,"Content-Type":content_type})
        with self.opener.open(req,timeout=60) as response:
            limit=32*1024*1024
            body=response.read(limit+1)
            if len(body)>limit:raise Failure("moi_report_size_limit")
            return body

    def file(self,fid):
        if not re.fullmatch(r"[0-9a-f-]{36}",fid):raise Failure("moi_file_id_invalid")
        return self.binary("/catalog/file/download",{"file_id":fid})

    def upload(self,name,raw):
        boundary="moi"+uuid.uuid4().hex
        body=("--"+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+name+'"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+raw+("\r\n--"+boundary+"--\r\n").encode()
        result=json.loads(self.binary("/catalog/file/upload",raw=body,content_type="multipart/form-data; boundary="+boundary))
        if result.get("code") not in ("OK",0,200):raise Failure("moi_upload_rejected")
        fid=result["data"]["file_id"]
        self.request("/catalog/file/create",{"volume_id":130001,"file_ids":[fid]})
        if self.file(fid)!=raw:raise Failure("moi_uploaded_readback_mismatch")
        return {"file_id":fid,"bytes":len(raw),"sha256":sha256(raw),"readback_verified":True}

def main():
    out=Path("out")
    out.mkdir(exist_ok=True)
    status={"schema":"matrix_cloud_report_publication_v1","sent":False,"status":"running"}
    try:
        api=ReportAPI(os.environ.get("MOI_API_KEY",""))
        fid=os.environ.get("MATRIX_ACCEPTANCE_FILE_ID","")
        expected=os.environ.get("MATRIX_ACCEPTANCE_SHA256","")
        if not fid or not expected:raise Failure("accepted_report_batch_required")
        raw=api.file(fid)
        if sha256(raw)!=expected:raise Failure("source_acceptance_hash_mismatch")
        batch=json.loads(raw)
        historical=os.environ.get("MATRIX_HISTORICAL_PUBLICATION_TEST")=="true"
        files={(repo,kind):api.file(result["artifacts"][kind]["file_id"]) for repo,result in batch["results"].items() for kind in ("employee","details","osv")}
        os.environ["MATRIX_PUBLICATION_LOCATION"]="GitHub Actions cloud runner"
        with tempfile.TemporaryDirectory() as tmp:
            receipt,preview=publish(api,batch,files,tmp,"node",historical)
            suffix="-historical-verification-"+os.environ.get("GITHUB_RUN_ID","manual") if historical else ""
            name="matrix-security-report-share-"+batch["date"].replace("-","")+suffix+".json"
            preview_name=name[:-5]+"-message.txt"
            message_artifact=api.upload(preview_name,preview.encode())
            receipt.update(source_acceptance_file_id=fid,message_artifact=message_artifact)
            publication_artifact=api.upload(name,json.dumps(receipt,ensure_ascii=False,indent=2).encode())
        # Logs and public artifacts contain only counts, fixed error codes and opaque file IDs.
        status.update(status="passed",report_date=batch["date"],historical_publication_test=historical,
                      all_source_hashes_verified=True,minio_report_readback_verified=True,login_free_verified=True,
                      message_bytes=receipt["message_bytes"],publication_file_id=publication_artifact["file_id"],
                      daily_automation_ready=False)
    except Exception as exc:
        status.update(status="failed",error=str(exc) if isinstance(exc,(Failure,ValueError)) else type(exc).__name__)
    status["finished_at_utc"]=dt.datetime.now(dt.timezone.utc).isoformat()
    (out/"moi-cloud-report-publication-receipt.json").write_text(json.dumps(status,indent=2)+"\n")
    print(json.dumps(status))
    return 0 if status["status"]=="passed" else 1

if __name__=="__main__":raise SystemExit(main())
