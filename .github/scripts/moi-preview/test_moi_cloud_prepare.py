import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import moi_archive_preview as preview
import moi_cloud_prepare as cloud
import moi_repo_scan as exchange
from test_moi_archive_preview import fixture


class CloudPreparation(unittest.TestCase):
    def test_missing_uploads_are_reported_as_unknown_not_clean(self):
        class MOI:
            def named_files(self, name, fuzzy=False):
                return []
        scans = cloud.collect_uploads(MOI(), "2026-10-19", dt.datetime(2026, 10, 19, 9, tzinfo=cloud.LOCAL))
        for row in scans.values():
            self.assertEqual("pending", row["status"])
            self.assertIsNone(row["hits"])
        body = cloud.body_for(scans, "2026-10-19").decode()
        self.assertIn("统计未知", body)
        self.assertNotIn("漏洞命中：0", body)

    def test_rejected_manifest_is_explicit_scan_failure(self):
        with patch.object(exchange, "read_scan", side_effect=exchange.ScanError("source_file_readback_mismatch")):
            scans = cloud.collect_uploads(None, "2026-10-19", cloud.now())
        for row in scans.values():
            self.assertEqual("scan_failed", row["status"])
            self.assertIsNone(row["hits"])
            self.assertEqual("source_file_readback_mismatch", row["error"])

    def test_aggregation_needs_no_github_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.getcwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "CUIShaoXin/matrixone",
                         "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "MOI_API_KEY": "private-test-key",
                         "REPORT_DATE": "", "WAIT_FOR_CLOUD_RUNS": "false", "GITHUB_TOKEN": "",
                         "GITHUB_OUTPUT": "", "GITHUB_STEP_SUMMARY": "", "SCAN_GITHUB_TOKEN": ""}), \
                     patch.object(cloud.MOI, "named_file", return_value=None), \
                     patch.object(cloud.MOI, "upload"), \
                     patch.object(cloud, "collect_uploads", side_effect=exchange.ScanError("source_read_reached")):
                    self.assertEqual(1, cloud.main())
                receipt = Path("out/moi-cloud-prepare-receipt.json").read_text()
                self.assertIn("source_read_reached", receipt)
                self.assertNotIn("private-test-key", receipt)
            finally:
                os.chdir(old)

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
