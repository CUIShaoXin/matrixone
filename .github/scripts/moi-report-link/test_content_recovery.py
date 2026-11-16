import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from cloud_daily import Failure, kb_content_recovery_allowed, json_bytes
from cloud_publish import verify_batch


DATE = '2026-11-16'
REPOS = ('matrixone', 'taas', 'matrixflow')


def batch(recovery=True):
    result = {}
    files = {}
    for index, repo in enumerate(REPOS, 1):
        commit = str(index) * 40
        facts = dict(report_date_shanghai=DATE, input_files=1,
                     queried_package_versions=2, affected_component_names=3,
                     unique_advisory_alias_groups=4)
        scan = dict(status='declared_version_queries_completed', commit=commit,
                    execution_location='MOI cloud Python worker',
                    manifest_integrity_verified=True, source_commit_verified=True,
                    private_dependency_source_downloaded=False,
                    repository_code_executed=False, facts=facts)
        raw = json_bytes(scan)
        employee, details = b'employee', b'details'
        evidence = lambda body: dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        result[repo] = dict(commit=commit, independent_readback_verified=True,
                            kb_marker_retrieved=not recovery,
                            knowledge_ingestion_verified=not recovery,
                            content_recovery=recovery,
                            counts={key: facts[key] for key in
                                    ('input_files', 'queried_package_versions',
                                     'affected_component_names', 'unique_advisory_alias_groups')},
                            artifacts=dict(osv=evidence(raw), employee=evidence(employee),
                                           details=evidence(details)))
        files[(repo, 'osv')] = raw
        files[(repo, 'employee')] = employee
        files[(repo, 'details')] = details
    return dict(date=DATE, workspace='fd3f15fe-3ac3-1c8c-5020-dffec978a0cb',
                knowledge_base_id=80001, three_repository_reports_accepted=True,
                daily_cloud_download_verified=True, content_recovery=recovery,
                results=result), files


class ContentRecoveryTests(unittest.TestCase):
    def test_only_kb_unavailability_can_enter_recovery(self):
        with patch.dict('os.environ', {'MATRIX_CONTENT_RECOVERY': 'auto'}):
            self.assertTrue(kb_content_recovery_allowed(Failure('moi_http_500')))
            self.assertTrue(kb_content_recovery_allowed(Failure('knowledge_ingestion_deadline')))
            self.assertFalse(kb_content_recovery_allowed(ValueError('invalid_model_json')))
        with patch.dict('os.environ', {'MATRIX_CONTENT_RECOVERY': 'true'}):
            self.assertTrue(kb_content_recovery_allowed(Failure('knowledge_ingestion_deadline')))
            self.assertFalse(kb_content_recovery_allowed(Failure('moi_http_500')))
        with patch.dict('os.environ', {}, clear=True):
            self.assertFalse(kb_content_recovery_allowed(Failure('moi_http_500')))

    def test_content_batch_can_omit_only_kb_evidence(self):
        value, files = batch(recovery=True)
        self.assertTrue(verify_batch(value, files, DATE))
        broken = copy.deepcopy(value)
        broken['results']['matrixflow']['kb_marker_retrieved'] = True
        with self.assertRaisesRegex(ValueError, 'kb_recovery_state_mismatch'):
            verify_batch(broken, files, DATE)
        broken = copy.deepcopy(value)
        broken['results']['taas']['independent_readback_verified'] = False
        with self.assertRaisesRegex(ValueError, 'source_unaccepted'):
            verify_batch(broken, files, DATE)

    def test_full_batch_still_requires_kb_and_states_cannot_be_mixed(self):
        value, files = batch(recovery=False)
        self.assertTrue(verify_batch(value, files, DATE))
        broken = copy.deepcopy(value)
        broken['results']['matrixone']['kb_marker_retrieved'] = False
        with self.assertRaisesRegex(ValueError, 'source_unaccepted'):
            verify_batch(broken, files, DATE)
        broken = copy.deepcopy(value)
        broken['results']['matrixone']['content_recovery'] = True
        with self.assertRaisesRegex(ValueError, 'content_recovery_mismatch'):
            verify_batch(broken, files, DATE)


if __name__ == '__main__':
    unittest.main()
