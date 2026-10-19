import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import moi_archive_preview as preview
import moi_cloud_prepare as cloud
from test_moi_archive_preview import fixture


def report():
    return cloud.pack({"results": [{"packages": [{"package": {"name": "example"},
        "vulnerabilities": [{"id": "GHSA-example", "aliases": ["CVE-2026-0000"]}]}]}]})


def run_fixture():
    return dict(id=123, path=cloud.CONFIG["matrixone"][2], head_branch="main", run_number=4,
                run_attempt=2, created_at="2026-10-18T23:30:00Z", status="completed", conclusion="success")


def zip_files(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    return buffer.getvalue()


class CloudPreparation(unittest.TestCase):
    def test_beijing_day_includes_previous_utc_evening(self):
        run = run_fixture()
        current = dt.datetime(2026, 10, 19, 8, tzinfo=cloud.LOCAL)
        self.assertEqual(run, cloud.fresh_run([run], cloud.CONFIG["matrixone"], "2026-10-19", current))

    def test_latest_failed_or_pending_run_never_falls_back_to_success(self):
        old = run_fixture()
        latest = dict(old, id=124, created_at="2026-10-19T00:00:00Z", status="in_progress", conclusion=None)
        current = dt.datetime(2026, 10, 19, 9, tzinfo=cloud.LOCAL)
        self.assertEqual(latest, cloud.fresh_run([old, latest], cloud.CONFIG["matrixone"], "2026-10-19", current))
        self.assertIsNone(cloud.fresh_run([old], cloud.CONFIG["matrixone"], "2026-10-20", current))

    def test_wrong_branch_and_workflow_are_not_candidates(self):
        current = dt.datetime(2026, 10, 19, 9, tzinfo=cloud.LOCAL)
        for change in [{"head_branch": "dev"}, {"path": "unrelated.yml"}]:
            self.assertIsNone(cloud.fresh_run([dict(run_fixture(), **change)], cloud.CONFIG["matrixone"], "2026-10-19", current))

    def test_echoed_private_summary_is_not_actual_output(self):
        with self.assertRaises(preview.PreviewError):
            cloud.scan_summary("taas", 'print(\'SECURITY_SCAN_SUMMARY={"repository":"matrixorigin/taas"}\')')
        with self.assertRaises(preview.PreviewError):
            cloud.scan_summary("taas", '2026-10-19T00:00:00Z SECURITY_SCAN_SUMMARY={"repository":"another/repo"}')

    def test_archive_zip_rejects_traversal_and_duplicate_filenames(self):
        for files in [{"../osv-results.json": report()}, {"a/osv-results.json": report(), "b/osv-results.json": report()}]:
            with self.assertRaises(preview.PreviewError):
                cloud.artifact_files(zip_files(files))

    def test_artifact_requires_both_raw_and_stderr(self):
        with self.assertRaises(preview.PreviewError):
            cloud.artifact_files(zip_files({"osv-results.json": report()}))

    def test_manifest_rejects_symlink_path_and_hash_injection(self):
        for path, mode, sha in [("../go.mod", "100644", "a" * 40), ("go.mod", "120000", "a" * 40),
                                ("go.mod", "100644", "x?recursive=1")]:
            with self.assertRaises(preview.PreviewError):
                cloud.safe_manifest(dict(path=path, mode=mode, sha=sha))

    def test_snapshot_hash_mismatch_prevents_scanner(self):
        class GitHub:
            def read(self, path):
                if "/commits/" in path:
                    return {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}
                if "/git/trees/" in path:
                    return {"truncated": False, "tree": [{"path": "go.mod", "type": "blob", "mode": "100644", "sha": "c" * 40, "size": 1}]}
                return {"encoding": "base64", "content": "eA=="}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(preview.PreviewError, "integrity"):
                cloud.snapshot(GitHub(), Path(directory))

    def test_scanner_receives_no_tokens_and_retains_partial_coverage(self):
        process = subprocess.CompletedProcess([], 1, report(), b"Error during extraction: a/requirements.txt")
        manifest = {"commit": "a" * 40, "files": [dict(path="go.mod", sha="b" * 40, size=1)]}
        with patch.object(cloud, "snapshot", return_value=manifest), \
             patch.object(cloud.subprocess, "run", return_value=process) as call, \
             patch.dict(os.environ, {"MOI_API_KEY": "private", "SCAN_GITHUB_TOKEN": "private", "GITHUB_TOKEN": "private"}):
            result = cloud.scan_matrixflow(None)
        self.assertEqual("scan_partial", result["status"])
        self.assertEqual((1, 1, 1), tuple(result[k] for k in ("hits", "unique_ids", "packages")))
        self.assertTrue(result["snapshot_verified"])
        self.assertFalse({"MOI_API_KEY", "SCAN_GITHUB_TOKEN", "GITHUB_TOKEN"} & call.call_args.kwargs["env"].keys())

    def test_unavailable_and_scan_failure_counts_are_null(self):
        for status in ["scan_failed", "unavailable", "pending"]:
            row = cloud.failed("taas", "permission_or_scan_failure", status)
            self.assertEqual([None, None, None], [row[k] for k in ("hits", "unique_ids", "packages")])
            message = cloud.body_for({n: cloud.failed(n, "blocked", status) for n in cloud.schema.REPOS}, "2026-10-19").decode()
            self.assertNotIn("漏洞命中：0", message)
            self.assertIn("统计未知", message)

    def test_missing_private_credentials_fail_before_moi_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.getcwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "CUIShaoXin/matrixone",
                         "GITHUB_RUN_ATTEMPT": "1", "MOI_API_KEY": "sensitive-test-key", "SCAN_GITHUB_TOKEN": "", "REPORT_DATE": "",
                         "GITHUB_STEP_SUMMARY": "", "GITHUB_OUTPUT": ""}), \
                     patch.object(cloud.MOI, "named_file", return_value=None), \
                     patch.object(cloud.MOI, "upload") as upload:
                    self.assertEqual(1, cloud.main())
                upload.assert_not_called()
                text = Path("out/moi-cloud-prepare-receipt.json").read_text()
                self.assertNotIn("sensitive-test-key", text)
                self.assertIn("private_repository_token_required", text)
            finally:
                os.chdir(old)

    def test_changed_download_never_counts_as_verified_upload(self):
        client = cloud.MOI("test")
        with patch.object(client, "named_file", return_value="11111111-1111-1111-1111-111111111111"), \
             patch.object(client, "file", return_value=b"modified"):
            with self.assertRaisesRegex(preview.PreviewError, "readback_mismatch"):
                client.upload("example.json", b"original")

    def test_partial_archive_handoff_keeps_gap_information(self):
        handoff, _ = fixture()
        handoff["archive_receipt"]["archive_status"] = "archived_with_gaps"
        handoff["daily_report"]["archive_status"] = "archived_with_gaps"
        preview.validate_handoff(handoff, "2026-10-19")
        handoff["archive_receipt"]["archive_status"] = "pending"
        with self.assertRaises(preview.PreviewError):
            preview.validate_handoff(handoff, "2026-10-19")

    def test_native_workflow_replaces_historical_defaults(self):
        payload = {"archive_batch_id": "cloud_batch"}
        class MOI:
            def get(self, path):
                if path == cloud.PREFIX:
                    nodes = {"step_" + str(i): {"id": "moi:data.sql.process"} for i in range(1, 6)}
                    nodes.update(__start={}, __end={})
                    return {"code": "OK", "data": {"workflow": {"id": cloud.WORKFLOW,
                        "name": "Matrix_三仓库扫描结果归档", "execution_mode": "one_shot",
                        "workflow": {"nets": {"root": {"nodes": nodes}}}}}}
                return {"code": "OK", "data": {"result": {"status": "completed", "moi_case_id": "native-case"}}}
            def request(self, path, value):
                self.payload = value
                return {"code": "OK", "data": {"workflow_run": {"workflow_id": cloud.WORKFLOW,
                    "execution_mode": "one_shot", "execution_id": "11111111-1111-1111-1111-111111111111"}}}
        client = MOI()
        inputs = {k: "SELECT 'cloud_batch'" for k in ("matrixone_sql", "taas_sql", "matrixflow_sql", "daily_report_sql", "verify_sql")}
        with patch.object(cloud.schema, "sql_inputs", return_value=inputs):
            cloud.workflow_run(client, payload)
        self.assertTrue(client.payload["replace_saved_defaults"])
        self.assertEqual({"sql", "taas_sql", "matrixflow_sql", "daily_report_sql", "verify_sql"}, set(client.payload["values"]))

    def test_independent_readback_rejects_changed_counts(self):
        payload = {"archive_batch_id": "batch", "daily_report": {"message_sha256": "correct"}}
        for n in cloud.schema.REPOS:
            payload[n] = {"repository": "matrixorigin/" + n, "vulnerability_hits": None}
        rows = [dict(payload[n]) for n in cloud.schema.REPOS]
        rows[1]["vulnerability_hits"] = "0"
        class MOI:
            def sql(self, query):
                return rows if "scan_runs" in query else [payload["daily_report"]]
        with self.assertRaisesRegex(preview.PreviewError, "readback_mismatch"):
            cloud.archived_rows(MOI(), payload)


if __name__ == "__main__":
    unittest.main()
