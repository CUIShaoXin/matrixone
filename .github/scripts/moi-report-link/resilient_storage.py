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


class SignedObjects:
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
        import time
        for attempt in range(3):
            try:
                result = api.request("/connectors/get", {"id": CONNECTOR_ID}, timeout=35)
                if result["http_status"] != 200:
                    raise RuntimeError("moi_http_"+str(result['http_status']))
                connector = api.data(result)
                connector = connector.get("connector", connector)
                config = connector["config"]
                config = json.loads(config) if isinstance(config, str) else config
                return cls(config.get("s3", config.get("s3_config", {})))
            except Exception as exc:
                transient = isinstance(exc,(TimeoutError,urllib.error.URLError,ConnectionError)) or str(exc) in ('moi_http_429','moi_http_500','moi_http_502','moi_http_503','moi_http_504')
                if not transient or attempt == 2: raise
                time.sleep(2**attempt)

    def _path(self, key):
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError("unsafe_object_key")
        return urllib.parse.quote("/" + self.bucket + "/" + key, safe="/-_.~")

    def _signature(self, date, message):
        def hm(key, value):
            return hmac.new(key, value.encode(), hashlib.sha256).digest()

        key = hm(hm(hm(hm(("AWS4" + self._secret).encode(), date), self.region), "s3"), "aws4_request")
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    def call(self, method, key, raw=None, headers=None, response_limit=32 * 1024 * 1024, timeout=None, query=None):
        now = dt.datetime.now(dt.timezone.utc)
        stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        if key == "" and method == "GET" and query and "uploads" in query and query.get("prefix"):
            path = "/" + urllib.parse.quote(self.bucket, safe="-_.~")
        else:
            path = self._path(key)
        encoded = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote, safe="-_.~")
        hdr = {"host": self.host, "x-amz-content-sha256": sha256(raw or b""), "x-amz-date": stamp}
        hdr.update({k.lower(): str(v).strip() for k, v in (headers or {}).items()})
        signed = ";".join(sorted(hdr))
        canonical_headers = "".join(k + ":" + hdr[k] + "\n" for k in sorted(hdr))
        canonical = "\n".join([method, path, encoded, canonical_headers, signed, hdr["x-amz-content-sha256"]])
        scope = date + "/" + self.region + "/s3/aws4_request"
        message = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, sha256(canonical.encode())])
        hdr["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + self._access + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + self._signature(date, message)
        request = urllib.request.Request(self.endpoint + path + ("?"+encoded if encoded else ""), data=raw, headers=hdr, method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout or (180 if key.endswith(".zip") else 45)) as response:
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

import time
import threading
import xml.etree.ElementTree as ET
from pipeline_telemetry import emit, span

TRANSIENT = (TimeoutError, ConnectionError, urllib.error.URLError)
PART_SIZE = 8 * 1024 * 1024
ZIP_READ_LIMIT = 256 * 1024 * 1024
ZIP_READ_LOCK = threading.RLock()


def xml_values(raw, name):
    root = ET.fromstring(raw)
    return [x.text for x in root.iter() if x.tag.rsplit('}', 1)[-1] == name]


class Objects(SignedObjects):
    def call(self, method, key, raw=None, headers=None, response_limit=32*1024*1024, timeout=None, query=None):
        # Snapshot keys contain the date and fixed commit. Reuse only in this
        # process; every consumer still checks its expected size and SHA256.
        if method == 'GET' and key.startswith('snapshots/') and key.endswith('.zip') and raw is None and not headers and not query:
            with ZIP_READ_LOCK:
                cache = getattr(self, '_zip_reads', None)
                if cache is None:
                    self._zip_reads = cache = {}
                if key in cache:
                    result = cache[key]
                    if len(result[2]) > response_limit:
                        raise ValueError('report_object_exceeds_limit')
                    emit('archive_read_cache_hit', bytes=len(result[2]))
                    return result[0], dict(result[1]), result[2]
                result = self._call_uncached(method, key, raw, headers, response_limit, timeout, query)
                if result[0] == 200 and len(result[2]) <= ZIP_READ_LIMIT:
                    while cache and sum(len(v[2]) for v in cache.values()) + len(result[2]) > ZIP_READ_LIMIT:
                        cache.pop(next(iter(cache)))
                    cache[key] = result[0], dict(result[1]), result[2]
                return result
        return self._call_uncached(method, key, raw, headers, response_limit, timeout, query)

    def _call_uncached(self, method, key, raw=None, headers=None, response_limit=32*1024*1024, timeout=None, query=None):
        for attempt in range(3):
            try:
                with span('minio_zip' if key.endswith('.zip') else 'minio_artifact', method=method, request_bytes=len(raw or b''), attempt=attempt+1):
                    return super().call(method, key, raw, headers, response_limit, timeout, query)
            except TRANSIENT:
                # Uncertain writes must be reconciled by the transfer state machine.
                if method not in ('GET','HEAD') or attempt == 2: raise
            except RuntimeError as exc:
                if str(exc) not in ('minio_http_429','minio_http_500','minio_http_502','minio_http_503','minio_http_504') or method not in ('GET','HEAD','PUT') or attempt == 2: raise
            emit('network_retry', category='minio', method=method, attempt=attempt+1)
            time.sleep(2**attempt)

    def publish(self, key, raw, content_type):
        digest = sha256(raw)
        for attempt in range(3):
            try:
                self.call('PUT',key,raw,{'content-type':content_type,'content-disposition':'inline','cache-control':'private, max-age=300','x-amz-meta-sha256':digest})
            except TRANSIENT:
                emit('artifact_put_uncertain',attempt=attempt+1)
            try:
                status, headers, received = self.call('GET',key,response_limit=max(len(raw),32*1024*1024))
            except RuntimeError as exc:
                if str(exc) != 'minio_http_404': raise
                status,headers,received=404,{},b''
            if status == 200 and received == raw:
                return dict(key=key,bytes=len(raw),sha256=digest,readback_verified=True,content_type=headers.get('Content-Type'),content_disposition=headers.get('Content-Disposition'))
            time.sleep(attempt+1)
        raise ValueError('minio_report_readback_mismatch')

    def verify_object(self, key, size, digest):
        try:
            status, headers, _ = self.call('HEAD', key)
        except RuntimeError as exc:
            if str(exc) == 'minio_http_404':
                return False
            raise
        hdr = {k.lower(): v for k, v in headers.items()}
        if status != 200 or int(hdr.get('content-length', '-1')) != size or hdr.get('x-amz-meta-sha256') != digest:
            raise ValueError('archive_object_identity_conflict')
        raw = self.call('GET', key, response_limit=size, timeout=180)[2]
        if len(raw) != size or sha256(raw) != digest:
            raise ValueError('archive_object_hash_mismatch')
        return True

    def put_verified(self, key, raw, digest, transfer, save):
        if sha256(raw) != digest:
            raise ValueError('archive_input_hash_mismatch')
        if self.verify_object(key, len(raw), digest):
            transfer.update(status='verified'); save(); return
        if transfer.get('status') == 'verified':
            raise ValueError('verified_archive_missing')
        if len(raw) < PART_SIZE:
            for attempt in range(3):
                transfer.update(status='put_pending', attempt=attempt+1); save()
                try:
                    self.call('PUT', key, raw, {'content-type':'application/zip', 'x-amz-meta-sha256':digest}, timeout=180)
                except TRANSIENT:
                    # An uncertain write is reconciled before another PUT.
                    emit('upload_recovery', operation='put', attempt=attempt+1)
                if self.verify_object(key, len(raw), digest):
                    transfer.update(status='verified'); save(); return
                time.sleep(attempt+1)
            raise ValueError('archive_put_attempts_exhausted')
        if not transfer.get('upload_id'):
            for initiation in range(3):
                if transfer.get('status') == 'initiation_uncertain':
                    body = self.call('GET', '', query={'uploads':'','prefix':key})[2]
                    root = ET.fromstring(body)
                    if xml_values(body,'IsTruncated') == ['true']:
                        raise ValueError('multipart_initiation_listing_truncated')
                    ids = []
                    for upload in root.iter():
                        if upload.tag.rsplit('}',1)[-1] == 'Upload':
                            fields = {n.tag.rsplit('}',1)[-1]:n.text for n in upload}
                            if fields.get('Key') == key: ids.append(fields['UploadId'])
                    if len(ids) > 1: raise ValueError('multipart_initiation_ambiguous')
                    if ids:
                        transfer.update(upload_id=ids[0],status='uploading',parts={});save();break
                transfer.update(status='initiation_uncertain');save()
                try:
                    body = self.call('POST', key, headers={'content-type':'application/zip','x-amz-meta-sha256':digest},query={'uploads':''})[2]
                    ids = xml_values(body,'UploadId')
                    if len(ids) != 1 or not ids[0]: raise ValueError('multipart_upload_id_missing')
                    transfer.update(upload_id=ids[0],status='uploading',parts={});save();break
                except TRANSIENT:
                    emit('upload_recovery',operation='initiate',attempt=initiation+1)
            if not transfer.get('upload_id'): raise ValueError('multipart_initiation_attempts_exhausted')
        upload_id = transfer['upload_id']
        # ListParts reconciles a lost part response or a restarted cloud job.
        remote = self._parts(key, upload_id)
        expected_numbers = set(range(1, (len(raw)+PART_SIZE-1)//PART_SIZE+1))
        if set(remote)-expected_numbers:
            raise ValueError('multipart_unexpected_part')
        for number, offset in enumerate(range(0, len(raw), PART_SIZE), 1):
            part = raw[offset:offset+PART_SIZE]
            md5 = hashlib.md5(part, usedforsecurity=False).hexdigest()
            for attempt in range(3):
                found = remote.get(number)
                if found:
                    etag, size = found
                    if etag.strip('"') != md5 or size != len(part):
                        raise ValueError('multipart_part_identity_conflict')
                    transfer['parts'][str(number)] = etag; save(); break
                try:
                    _, hdr, _ = self.call('PUT', key, part, timeout=180, query={'partNumber':str(number),'uploadId':upload_id})
                    etag = next((v for k,v in hdr.items() if k.lower()=='etag'), '')
                    if etag.strip('"') != md5:
                        raise ValueError('multipart_part_checksum_mismatch')
                    remote[number] = (etag, len(part))
                except TRANSIENT:
                    emit('upload_recovery', operation='part', part=number, attempt=attempt+1)
                    remote = self._parts(key, upload_id)
                if number in remote:
                    etag, size = remote[number]
                    if etag.strip('"') != md5 or size != len(part):
                        raise ValueError('multipart_part_identity_conflict')
                    transfer['parts'][str(number)] = etag; save()
                    emit('upload_progress', part=number, verified_bytes=min(offset+len(part),len(raw)), total_bytes=len(raw))
                    break
                time.sleep(attempt+1)
            else:
                raise ValueError('multipart_part_attempts_exhausted')
        root = ET.Element('CompleteMultipartUpload')
        for number in sorted(expected_numbers):
            item = ET.SubElement(root, 'Part')
            ET.SubElement(item, 'PartNumber').text = str(number)
            ET.SubElement(item, 'ETag').text = transfer['parts'][str(number)]
        transfer.update(status='completion_pending'); save()
        for attempt in range(3):
            try:
                body = self.call('POST', key, ET.tostring(root), headers={'content-type':'application/xml'}, query={'uploadId':upload_id}, timeout=180)[2]
                if ET.fromstring(body).tag.rsplit('}',1)[-1] == 'Error':
                    raise ValueError('multipart_complete_embedded_error')
            except TRANSIENT:
                emit('upload_recovery', operation='complete', attempt=attempt+1)
            except RuntimeError as exc:
                if str(exc) != 'minio_http_404': raise
            if self.verify_object(key, len(raw), digest):
                transfer.update(status='verified'); save(); return
            time.sleep(attempt+1)
        raise ValueError('multipart_complete_attempts_exhausted')

    def _parts(self, key, upload_id):
        result = {}
        marker = 0
        while True:
            query = {'uploadId':upload_id, 'max-parts':'1000'}
            if marker: query['part-number-marker'] = str(marker)
            raw = self.call('GET', key, query=query)[2]
            root = ET.fromstring(raw)
            for part in root.iter():
                if part.tag.rsplit('}',1)[-1] == 'Part':
                    values = {n.tag.rsplit('}',1)[-1]:n.text for n in part}
                    result[int(values['PartNumber'])] = (values['ETag'],int(values['Size']))
            if xml_values(raw,'IsTruncated') != ['true']: return result
            next_marker = int(xml_values(raw,'NextPartNumberMarker')[0])
            if next_marker <= marker: raise ValueError('multipart_pagination_stalled')
            marker = next_marker
