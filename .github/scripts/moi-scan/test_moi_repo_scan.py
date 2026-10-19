import copy
import datetime as dt
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import moi_repo_scan as scan

CURRENT = dt.datetime(2026, 10, 19, 9, tzinfo=scan.LOCAL)
DATE = "2026-10-19"
RAW = scan.pack({"results": [{"packages": [
    {"package": {"name": "affected"}, "vulnerabilities": [{"id": "GHSA-example", "aliases": ["CVE-2026-0001"]}]},
    {"package": {"name": "unaffected"}, "vulnerabilities": []}]}]})


class MemoryMOI:
    def __init__(self):
        self.files = {}
        self.names = {}

    def upload(self, name, raw):
        if name in self.names:
            fid = self.names[name]
            scan.require(self.files[fid] == raw, "uploaded_file_readback_mismatch")
            return fid
        fid = str(uuid.uuid4())
        self.names[name], self.files[fid] = fid, raw
        return fid

    def file(self, fid):
        return self.files[fid]

    def named_files(self, name, fuzzy=False):
        return [dict(name=n, id=fid, volume_id=scan.VOLUME) for n, fid in self.names.items()
                if (name in n if fuzzy else name == n)]


def source(name="taas", run_id=123, attempt=1, failed=False, partial=False):
    execution, branch, workflow = scan.CONFIG[name]
    stderr = b"Error during extraction: dependency" if partial else b""
    result = scan.summarize(RAW, stderr, 2 if failed else 1)
    return dict(name=name, repository="matrixorigin/" + name, execution_repository=execution,
                branch=branch, commit="a" * 40, run=dict(id=run_id, path=workflow, head_branch=branch,
                    run_attempt=attempt, created_at="2026-10-18T23:30:00Z", event="schedule",
                    html_url="https://github.com/" + execution + "/actions/runs/" + str(run_id)),
                started_at="2026-10-19T07:31:00+08:00", finished_at="2026-10-19T07:33:00+08:00",
                scanner_version="2.7.0", coverage="OSV dependency scan", **result)


class RepositoryUpload(unittest.TestCase):
    def test_publish_and_aggregate_all_repositories_without_github_client(self):
        moi = MemoryMOI()
        for name in scan.CONFIG:
            original = source(name)
            receipt = scan.publish(moi, name, DATE, original, dict(raw=RAW, stderr=b""), CURRENT)
            result = scan.read_scan(moi, name, DATE, CURRENT)
            self.assertEqual("scan_uploaded", receipt["status"])
            self.assertEqual((1, 1, 1), tuple(result[k] for k in ("hits", "unique_ids", "packages")))
            self.assertEqual(RAW, result["raw"])
            self.assertEqual(original["run"], result["run"])
            self.assertFalse(receipt["sent"])

    def test_repeat_publish_reuses_identical_files_and_manifest(self):
        moi = MemoryMOI()
        first = scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        before = dict(moi.names)
        again = scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        self.assertEqual(before, moi.names)
        self.assertEqual(first, again)

    def test_partial_resolution_preserves_counts_and_coverage(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(partial=True),
                     dict(raw=RAW, stderr=b"Error during extraction: dependency"), CURRENT)
        result = scan.read_scan(moi, "taas", DATE, CURRENT)
        self.assertEqual("scan_partial", result["status"])
        self.assertEqual(1, result["hits"])

    def test_scanner_failure_publishes_null_counts_even_with_valid_empty_report(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(failed=True), dict(raw=RAW, stderr=b"failed"), CURRENT)
        result = scan.read_scan(moi, "taas", DATE, CURRENT)
        self.assertEqual("scan_failed", result["status"])
        self.assertEqual((None, None, None), tuple(result[k] for k in ("hits", "unique_ids", "packages")))

    def test_absent_upload_is_pending_with_null_counts(self):
        result = scan.read_scan(MemoryMOI(), "matrixflow", DATE, CURRENT)
        self.assertEqual("pending", result["status"])
        self.assertEqual((None, None, None), tuple(result[k] for k in ("hits", "unique_ids", "packages")))

    def test_later_failed_run_replaces_previous_success(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        scan.publish(moi, "taas", DATE, source(run_id=124, failed=True), dict(raw=RAW, stderr=b""), CURRENT)
        result = scan.read_scan(moi, "taas", DATE, CURRENT)
        self.assertEqual("scan_failed", result["status"])
        self.assertEqual(124, result["run"]["id"])

    def test_rerun_selects_exact_latest_attempt(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        scan.publish(moi, "taas", DATE, source(attempt=2), dict(raw=RAW, stderr=b""), CURRENT)
        self.assertEqual(2, scan.read_scan(moi, "taas", DATE, CURRENT)["run"]["run_attempt"])

    def test_changed_raw_file_is_rejected_without_using_previous_success(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        scan.publish(moi, "taas", DATE, source(run_id=124), dict(raw=RAW, stderr=b""), CURRENT)
        envelope = json.loads(moi.file(moi.names["repo-scan-v1-taas-20261019-124-1.json"]))
        moi.files[envelope["files"]["raw"]["file_id"]] = b"changed"
        with self.assertRaisesRegex(scan.ScanError, "source_file_readback_mismatch"):
            scan.read_scan(moi, "taas", DATE, CURRENT)

    def test_source_manifest_rejects_wrong_workspace_repo_branch_commit_and_date(self):
        moi = MemoryMOI()
        scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        base = json.loads(moi.file(moi.names["repo-scan-v1-taas-20261019-123-1.json"]))
        changes = [
            ("workspace_id", "another", False), ("report_date", "2026-10-18", False),
            ("repository", "matrixorigin/matrixflow", True), ("branch", "dev", True),
            ("commit", "invalid", True), ("finished_at", "2026-10-20T08:00:00+08:00", True),
        ]
        for field, value, nested in changes:
            with self.subTest(field=field):
                envelope = copy.deepcopy(base)
                (envelope["scan"] if nested else envelope)[field] = value
                with self.assertRaises(scan.ScanError):
                    scan.validate(envelope, "taas", DATE, CURRENT)

    def test_clean_report_is_distinct_from_missing_invalid_and_failed(self):
        empty = scan.pack({"results": []})
        self.assertEqual("clean", scan.summarize(empty, b"", 0)["status"])
        for raw, stderr, code in [(None, b"", 0), (b"broken", b"", 0), (empty, b"", 2), (empty, None, 0)]:
            result = scan.summarize(raw, stderr, code)
            self.assertEqual("scan_failed", result["status"])
            self.assertIsNone(result["hits"])

    def test_no_ready_manifest_is_published_after_a_file_upload_failure(self):
        moi = MemoryMOI()
        original = moi.upload
        def fail_stderr(name, raw):
            if name.endswith("-stderr.txt"):
                raise scan.ScanError("moi_transport_or_json_error")
            return original(name, raw)
        moi.upload = fail_stderr
        with self.assertRaises(scan.ScanError):
            scan.publish(moi, "taas", DATE, source(), dict(raw=RAW, stderr=b""), CURRENT)
        self.assertEqual("pending", scan.read_scan(moi, "taas", DATE, CURRENT)["status"])

    def test_existing_remote_file_must_match_before_reuse(self):
        client = scan.MOI("test-key")
        with patch.object(client, "named_file", return_value="11111111-1111-1111-1111-111111111111"), \
             patch.object(client, "file", return_value=b"changed"):
            with self.assertRaisesRegex(scan.ScanError, "readback_mismatch"):
                client.upload("example.json", b"original")

    def test_receipt_never_contains_api_key_or_raw_report_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.getcwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": "wrong/repo", "MOI_API_KEY": "private-test-key",
                                             "GITHUB_STEP_SUMMARY": ""}):
                    self.assertEqual(1, scan.main())
                receipt = Path("out/moi-scan-upload-receipt.json").read_text()
                self.assertNotIn("private-test-key", receipt)
                self.assertNotIn("affected", receipt)
                self.assertIn("unexpected_execution_repository", receipt)
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()

