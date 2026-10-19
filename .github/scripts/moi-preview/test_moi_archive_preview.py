import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import moi_archive_preview as preview


def fixture():
    body = "test report\npartial coverage retained\n".encode()
    file_id = "11111111-1111-1111-1111-111111111111"
    sha = hashlib.sha256(body).hexdigest()
    batch = "test_batch"
    date = "2026-10-19"
    handoff = {
        "schema_version": 1, "mode": "preview", "send_authorized": False,
        "workspace_id": preview.WORKSPACE, "agent_id": preview.AGENT,
        "report_date": date, "archive_batch_id": batch,
        "message": {"file_id": file_id, "sha256": sha, "size_bytes": len(body)},
        "archive_receipt": {"workspace_id": preview.WORKSPACE, "archive_status": "archived",
                            "readback_verified": True, "files_verified": True,
                            "scan_rows": 3, "daily_rows": 1, "job_id": "job", "execution_id": "execution",
                            "archive_batch_id": batch, "report_date": date,
                            "message_file_id": file_id, "message_sha256": sha},
        "daily_report": {"archive_batch_id": batch, "report_date": date,
                         "message_file_id": file_id, "message_sha256": sha},
        "scan_runs": [{"repository": repo, "branch": branch, "archive_batch_id": batch,
                       "report_date": date, "scan_status": "scan_partial"}
                      for repo, branch in [("matrixorigin/matrixone", "main"),
                                           ("matrixorigin/taas", "main"),
                                           ("matrixorigin/matrixflow", "dev")]],
    }
    return handoff, body


def response(handoff, body, key):
    return {"schema_version": 1, "mode": "preview", "send_authorized": False,
            "sent": False, "validation": "PASS", "trigger_request_key": key,
            "workspace_id": preview.WORKSPACE, "agent_id": preview.AGENT,
            "report_date": handoff["report_date"], "archive_batch_id": handoff["archive_batch_id"],
            "message_file_id": handoff["message"]["file_id"], "source": "MOI_volume_download",
            "measured_sha256": hashlib.sha256(body).hexdigest(), "measured_size_bytes": len(body),
            "tool_arguments": {"msg_type": "text", "content": body.decode()}}


class Boundaries(unittest.TestCase):
    def test_numeric_and_string_success_codes(self):
        self.assertTrue(preview.success({"code": 0}))
        self.assertTrue(preview.success({"code": "OK"}))
        self.assertFalse(preview.success({"code": False}))
        self.assertFalse(preview.success({"code": 5}))

    def test_unverified_archive_rejected(self):
        handoff, _ = fixture()
        handoff["archive_receipt"]["readback_verified"] = False
        with self.assertRaises(preview.PreviewError):
            preview.validate_handoff(handoff, "2026-10-19")

    def test_send_handoff_rejected(self):
        handoff, _ = fixture()
        handoff["mode"] = "send"
        with self.assertRaises(preview.PreviewError):
            preview.validate_handoff(handoff, "2026-10-19")

    def test_date_and_batch_mismatch_rejected(self):
        for mutation in [lambda h: h.update(report_date="2026-10-18"),
                         lambda h: h["daily_report"].update(archive_batch_id="other")]:
            handoff, _ = fixture()
            mutation(handoff)
            with self.assertRaises(preview.PreviewError):
                preview.validate_handoff(handoff, "2026-10-19")

    def test_wrong_repository_branch_rejected(self):
        handoff, _ = fixture()
        handoff["scan_runs"][2]["branch"] = "main"
        with self.assertRaises(preview.PreviewError):
            preview.validate_handoff(handoff, "2026-10-19")

    def test_no_shell_or_arbitrary_file_source(self):
        class Client:
            def messages(self, *a, **kw):
                raise AssertionError("Unvalidated source must not reach network")
        with self.assertRaises(preview.PreviewError):
            preview.load_handoff(Client(), "$(anything)", "", "2026-10-19")

    def test_result_must_preserve_every_byte(self):
        handoff, body = fixture()
        key = preview.request_key(handoff)
        result = response(handoff, body, key)
        preview.validate_result(result, handoff, key, body)
        result["tool_arguments"]["content"] = result["tool_arguments"]["content"].rstrip()
        with self.assertRaises(preview.PreviewError):
            preview.validate_result(result, handoff, key, body)

    def test_extra_send_argument_rejected(self):
        handoff, body = fixture()
        key = preview.request_key(handoff)
        result = response(handoff, body, key)
        result["tool_arguments"]["instance_name"] = "not_a_parameter"
        with self.assertRaises(preview.PreviewError):
            preview.validate_result(result, handoff, key, body)

    def test_request_identity_stable_across_upstream_trigger_ids(self):
        handoff, _ = fixture()
        original = preview.request_key(handoff)
        handoff["trigger_request_key"] = "unrelated_previous_preview"
        self.assertEqual(original, preview.request_key(handoff))
        request = preview.make_request(handoff, original)
        self.assertEqual(original, request["params"]["idempotencyKey"])
        self.assertIn('"send_authorized": false', request["params"]["message"]["parts"][0]["text"])

    def test_existing_task_does_not_submit(self):
        handoff, body = fixture()
        task = {"kind": "task", "id": "task", "contextId": "ctx", "status": {"state": "completed"}}
        class Client:
            def request(self, path, payload, **kw):
                if payload["method"] != "tasks/get":
                    raise AssertionError("Must not submit again")
                return {"result": task}
        receipt = {}
        with patch.object(preview, "find_existing", return_value=("task", "ctx")), \
                patch.object(preview, "validate_task"):
            preview.run(Client(), handoff, body, receipt)
        self.assertEqual(0, receipt["submission_attempts_this_run"])

    def test_unknown_submission_recovers_without_post_retry(self):
        handoff, body = fixture()
        sent = []
        class Client:
            def request(self, path, payload, **kw):
                sent.append(payload["method"])
                if payload["method"] == "message/send":
                    raise preview.PreviewError("api_transport_or_json_error")
                return {"result": {"kind": "task", "id": "task", "contextId": "ctx",
                                   "status": {"state": "completed"}}}
        with patch.object(preview, "find_existing", side_effect=[None, ("task", "ctx")]), \
                patch.object(preview, "validate_task"), patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "1"}):
            preview.run(Client(), handoff, body, {})
        self.assertEqual(["message/send", "tasks/get"], sent)

    def test_workflow_rerun_without_recoverable_task_refuses_post(self):
        handoff, body = fixture()
        with patch.object(preview, "find_existing", return_value=None), \
                patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.assertRaises(preview.PreviewError):
                preview.run(None, handoff, body, {})

    def test_errors_do_not_publish_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            with patch.dict(os.environ, {"REPORT_DATE": "2026-10-19", "MOI_API_KEY": "test-sensitive-token",
                                         "RECEIPT_PATH": str(output), "GITHUB_STEP_SUMMARY": ""}), \
                    patch.object(preview.Client, "get", side_effect=Exception("test-sensitive-token")):
                self.assertEqual(1, preview.main())
            self.assertNotIn("test-sensitive-token", output.read_text())


if __name__ == "__main__":
    unittest.main()
