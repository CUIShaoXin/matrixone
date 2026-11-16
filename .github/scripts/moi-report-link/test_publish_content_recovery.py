import datetime as dt
import json
import types
import unittest
from unittest.mock import Mock, patch

from api_port_review import publish_report
from cloud_daily import json_bytes


class PublishContentRecoveryTests(unittest.TestCase):
    def run_publish(self, recovery):
        date = '2026-11-16'
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).replace(microsecond=0)
        raw = b'<html><body><section id="components"></section><footer>scope</footer></body></html>'
        md = b'MATRIX-API-PORT-20261116-daily-test\nreport'
        details = [dict(repository='matrixone', commit='1' * 40,
                        expires_at_utc=expiry.isoformat())]
        artifact = dict(file_id='11111111-1111-4111-8111-111111111111', bytes=len(md),
                        sha256=__import__('hashlib').sha256(md).hexdigest())
        publication_artifact = dict(file_id='22222222-2222-4222-8222-222222222222')
        saved = {}
        job = types.SimpleNamespace(
            state=dict(date=date, run_id='daily-test', source_id='source-fid',
                       source_sha256='a' * 64, unified_current_batch=True),
            journal=types.SimpleNamespace(key='receipts/test/reviews/checkpoint.json',
                                          value={}, save=lambda: None),
            api=Mock(), objects=Mock(), component_osv={})
        job.store = lambda name, value: saved.setdefault(name, value)
        job.objects.publish.return_value = dict(key='reports/test/main.html', bytes=len(raw),
                                                sha256='b' * 64)
        job.objects.presign.return_value = ('https://example.test/report', expiry.isoformat())
        source = dict(report_date=date, commits={r: str(i) * 40 for i, r in
                                                enumerate(('matrixone', 'taas', 'matrixflow'), 1)},
                      content_recovery=recovery, kb_marker_retrieved=not recovery,
                      knowledge_ingestion_verified=not recovery)
        results = {r: dict(findings=[]) for r in source['commits']}
        with patch('component_details.publish_and_link',
                   return_value=(raw, details, '', expiry)), \
             patch('api_port_review.Runner') as runner, \
             patch('api_port_review.verify_login_free', return_value={'http': 200}), \
             patch('native_upload.upload_named_once', return_value=publication_artifact), \
             patch('knowledge_gate.ensure_sources') as ensure, \
             patch('knowledge_gate.audit', return_value={'verified': True}) as audit:
            runner.return_value.workflow.return_value = {'report': (artifact, md + b'\n\n')}
            if not recovery:
                audit.return_value = {'verified': True}
            receipt = publish_report(job, source, raw, results,
                                     rendered=(raw, md, 'MATRIX-API-PORT-20261116-daily-test', 0))
        return receipt, saved, ensure, audit

    def test_recovery_skips_only_kb_and_keeps_visible_notice(self):
        receipt, saved, ensure, audit = self.run_publish(True)
        ensure.assert_not_called()
        audit.assert_not_called()
        self.assertFalse(receipt['kb_marker_retrieved'])
        self.assertFalse(receipt['knowledge_ingestion_verified'])
        self.assertFalse(receipt['native_final_citations_verified'])
        self.assertTrue(receipt['content_recovery'])
        self.assertIn('KB 入库与原生最终引用待平台恢复',
                      saved['matrix-security-daily.html'].decode())
        self.assertIn('markdown_artifact', receipt)

    def test_full_publication_still_requires_real_kb_audit(self):
        receipt, saved, ensure, audit = self.run_publish(False)
        ensure.assert_called_once()
        audit.assert_called_once()
        self.assertTrue(receipt['kb_marker_retrieved'])
        self.assertTrue(receipt['knowledge_ingestion_verified'])
        self.assertTrue(receipt['native_final_citations_verified'])
        self.assertFalse(receipt['content_recovery'])


if __name__ == '__main__':
    unittest.main()
