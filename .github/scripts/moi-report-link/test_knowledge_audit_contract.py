"""New multi-source tasks improve the contract; immutable old requests survive."""
import hashlib
import json
import unittest
from unittest.mock import patch

from knowledge_gate import audit
from test_pipeline_recovery import Job,Model

LEGACY_HASH='801fda7a3b04da6fc17409bf2d8c33049eff98f541b8bbb430e0fbfb02a0d79a'


class AuditContractTests(unittest.TestCase):
    def test_existing_v2_keeps_exact_contract_phase_and_context(self):
        job=Job(Model([]));job.state['model_tasks']={'repo_kb_files_scope_v2':{'original':'retained'}}
        targets=[dict(file_id='one',marker='first'),dict(file_id='two',marker='second')]
        with patch('kimi_recovery.run_review',return_value='verified') as run:
            self.assertEqual(audit(job,targets,'files'),'verified')
        args=run.call_args.args
        self.assertEqual(args[2],'kb_files_scope_v2')
        self.assertEqual(hashlib.sha256(args[4].encode()).hexdigest(),LEGACY_HASH)
        self.assertEqual(args[3],json.dumps(targets,sort_keys=True))
        self.assertEqual(job.state['model_tasks']['repo_kb_files_scope_v2'],{'original':'retained'})
    def test_new_phase_is_persisted_by_real_review_and_reused_on_resume(self):
        api=Model([dict(id='t1',status={'state':'completed'}),dict(id='t1',status={'state':'completed'})])
        job=Job(api);targets=[dict(file_id='one',marker='first'),dict(file_id='two',marker='second')]
        with patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]),\
             patch('cloud_daily.verify_rag',return_value='verified'):
            self.assertEqual(audit(job,targets,'files'),'verified')
            self.assertEqual(audit(job,targets,'files'),'verified')
        self.assertIn('repo_kb_files_scope_v3',job.state['model_tasks'])
        self.assertNotIn('repo_kb_files_scope_v2',job.state['model_tasks'])
        self.assertNotEqual(job.state['model_tasks']['repo_kb_files_scope_v3']['contract_sha256'],LEGACY_HASH)
        self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])


if __name__=='__main__':unittest.main()
