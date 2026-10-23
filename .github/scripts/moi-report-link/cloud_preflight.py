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


from resilient_storage import Objects


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

"""ZIP stage for a future managed MOI runner.

The deployed MOI tools currently cannot supply the required authenticated
archive and object-store adapters. This module is not a deployed daily job.
Adapters must keep credentials inside their managed connections.
"""
from dataclasses import dataclass
from datetime import datetime,timezone
from pathlib import PurePosixPath
import hashlib,json,re,tempfile,time,zipfile
from typing import Protocol,BinaryIO

@dataclass(frozen=True)
class Repository:
    owner:str
    name:str
    branch:str

REPOSITORIES=(Repository('matrixorigin','matrixone','main'),Repository('matrixorigin','taas','main'),Repository('matrixorigin','matrixflow','dev'))

class ManagedGitHub(Protocol):
    def branch_commit(self,repository:Repository)->str:...
    def download_zip(self,repository:Repository,commit:str,destination:BinaryIO)->None:...

class ManagedObjects(Protocol):
    def put_stream(self,key:str,stream:BinaryIO,size:int,sha256:str)->None:...
    def get_stream(self,key:str)->BinaryIO:...
    def put_receipt(self,key:str,receipt:dict)->None:...

MANIFEST=re.compile(r'(^|/)(go\.mod|go\.sum|package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|pom\.xml|gradle\.lockfile|packages\.lock\.json|composer\.lock|Gemfile\.lock|[^/]*\.csproj)$')

def digest_stream(stream,rewind=True):
    if rewind:stream.seek(0)
    h=hashlib.sha256();count=0
    while True:
        block=stream.read(1024*1024)
        if not block:break
        h.update(block);count+=len(block)
    if rewind:stream.seek(0)
    return count,h.hexdigest()

def validate_zip(stream,expected_commit,max_archive_bytes=1024*1024*1024,max_expanded_bytes=4*1024*1024*1024,max_entries=100000):
    count,digest=digest_stream(stream)
    if count<=4 or count>max_archive_bytes:raise ValueError('archive_size_invalid')
    try:z=zipfile.ZipFile(stream)
    except zipfile.BadZipFile:raise ValueError('response_is_not_a_valid_zip')
    with z:
        entries=z.infolist()
        if not entries or len(entries)>max_entries:raise ValueError('archive_entry_count_invalid')
        if sum(x.file_size for x in entries)>max_expanded_bytes:raise ValueError('archive_expanded_size_limit')
        roots=set();seen=set();manifests=[]
        for item in entries:
            path=PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename:raise ValueError('unsafe_zip_path')
            if item.filename in seen:raise ValueError('duplicate_zip_path')
            seen.add(item.filename);roots.add(path.parts[0])
            if item.flag_bits&1:raise ValueError('encrypted_zip_not_supported')
            if not item.is_dir() and MANIFEST.search(item.filename):
                if item.file_size>16*1024*1024:raise ValueError('manifest_size_limit')
                raw=z.read(item);manifests.append({'path':'/'.join(path.parts[1:]),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        if len(roots)!=1:raise ValueError('archive_root_ambiguous')
        if z.comment.decode('ascii',errors='replace')!=expected_commit:raise ValueError('archive_commit_mismatch')
        if z.testzip() is not None:raise ValueError('archive_crc_failed')
        if not manifests:raise ValueError('no_dependency_manifest_found')
    stream.seek(0)
    return {'bytes':count,'sha256':digest,'commit':expected_commit,'zip_entries':len(entries),'crc_verified':True,'manifests':manifests}

def run(github:ManagedGitHub,objects:ManagedObjects,run_id:str,date_shanghai:str,sleep=time.sleep):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',run_id) or not re.fullmatch(r'\d{8}',date_shanghai):raise ValueError('invalid_run_identifier')
    results=[]
    for repository in REPOSITORIES:
        receipt={'repository':repository.owner+'/'+repository.name,'branch':repository.branch,'run_id':run_id,'date_shanghai':date_shanghai,'status':'failed','attempts':0,'private_dependency_source_downloaded':False}
        try:
            commit=github.branch_commit(repository)
            if not re.fullmatch(r'[0-9a-f]{40}',commit):raise ValueError('invalid_commit')
            key='snapshots/'+date_shanghai+'/'+repository.name+'/'+repository.name+'-'+commit+'-'+run_id+'.zip'
            for attempt in range(1,4):
                receipt['attempts']=attempt
                try:
                    with tempfile.TemporaryFile() as stream:
                        github.download_zip(repository,commit,stream)
                        verified=validate_zip(stream,commit)
                        objects.put_stream(key,stream,verified['bytes'],verified['sha256'])
                        with objects.get_stream(key) as readback:
                            size,sha=digest_stream(readback,rewind=False)
                        if size!=verified['bytes'] or sha!=verified['sha256']:raise ValueError('minio_readback_mismatch')
                        receipt.update(verified,key=key,status='verified',minio_readback_verified=True)
                    break
                except Exception:
                    if attempt==3:raise
                    sleep(2**attempt)
        except Exception as exc:
            # Exception messages may contain request URLs or credentials. Save only type.
            receipt['error_type']=type(exc).__name__
        receipt['finished_at']=datetime.now(timezone.utc).isoformat()
        objects.put_receipt('receipts/'+date_shanghai+'/'+run_id+'/'+repository.name+'.json',receipt)
        results.append(receipt)
    summary={'run_id':run_id,'date_shanghai':date_shanghai,'repositories':results,'all_three_verified':all(x['status']=='verified' for x in results),'eligible_for_full_three_repository_report':all(x['status']=='verified' for x in results)}
    objects.put_receipt('receipts/'+date_shanghai+'/'+run_id+'/summary.json',summary)
    return summary

"""Existing Actions secrets -> fixed GitHub ZIP -> existing MinIO, no group send."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
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

    def open(self, request, timeout, stage):
        for attempt in range(3):
            try:
                return self.opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 502, 503, 504) or attempt == 2:
                    raise
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLCertVerificationError):
                    raise Failure(stage + "_certificate_verification_failed") from None
                if attempt == 2:
                    raise Failure(stage + "_network_" + type(exc.reason).__name__) from None
            except TimeoutError:
                if attempt == 2:
                    raise Failure(stage + "_timeout") from None
            time.sleep(attempt + 1)

    def get(self, repository, path, binary=False):
        req = urllib.request.Request("https://api.github.com/repos/" + repository + path,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                     "User-Agent": "Matrix-MOI-ZIP-Preparation", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            response = self.open(req, timeout=40, stage="github_archive_redirect" if binary else "github_branch_metadata")
        except urllib.error.HTTPError as exc:
            if binary and exc.code in (301, 302, 303, 307, 308):
                url = urllib.parse.urlsplit(exc.headers.get("Location", ""))
                if url.scheme != "https" or url.hostname != "codeload.github.com" or url.username or url.password:
                    raise Failure("github_untrusted_archive_redirect") from None
                # Never forward GitHub Authorization to the archive endpoint.
                try:
                    response = self.open(urllib.request.Request(url.geturl()), timeout=60, stage="github_archive_download")
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
    from archive_transfer import prepare
    return prepare(github, objects, repository, run_id, date, validate_zip, Failure)


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

if __name__ == "__main__":
    raise SystemExit(main())
