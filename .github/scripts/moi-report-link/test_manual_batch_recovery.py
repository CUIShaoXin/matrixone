import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import daily_pipeline as pipeline
from cloud_daily import Failure


class ManualBatchRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(GITHUB_EVENT_NAME='workflow_dispatch',
                        MATRIX_PIPELINE_MODE='full', MATRIX_CONTENT_RECOVERY='true',
                        MATRIX_PIPELINE_RESUME_RUN_ID='daily-20261121',
                        MATRIX_EXPECTED_REPORT_DATE='2026-11-22', MOI_API_KEY='test')

    def test_manual_resume_preserves_business_date(self):
        self.assertEqual(pipeline.manual_recovery_date(self.env, '2026-11-22'), '2026-11-21')
        self.assertEqual(pipeline.manual_recovery_date(self.env, '2026-11-21'), '2026-11-21')
        for date in ('2026-11-20', '2026-11-23'):
            with self.assertRaisesRegex(Failure, 'manual_recovery_date_outside_window'):
                pipeline.manual_recovery_date(self.env, date)

    def test_schedule_is_not_eligible(self):
        for overrides in (dict(GITHUB_EVENT_NAME='schedule'), dict(MATRIX_SCHEDULED_BATCH='true'),
                          dict(MATRIX_PIPELINE_MODE='reviews'), dict(MATRIX_CONTENT_RECOVERY='auto')):
            self.assertIsNone(pipeline.manual_recovery_date(self.env | overrides, '2026-11-22'))

    def test_missing_previous_checkpoint_does_not_create_any_batch(self):
        objects = Mock()
        objects.call.side_effect = RuntimeError('minio_http_404')
        expected_clock = dt.datetime(2026, 11, 22, 0, 2, tzinfo=pipeline.preflight.LOCAL)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.env, clear=True), \
             patch.object(pipeline, 'Path', return_value=Path(tmp)), \
             patch.object(pipeline.dt, 'datetime', wraps=dt.datetime) as clock, \
             patch.object(pipeline, 'DailyAPI'), \
             patch.object(pipeline.preflight.Objects, 'from_workspace', return_value=objects):
            clock.now.return_value = expected_clock
            self.assertEqual(pipeline.main(), 1)
            status = json.loads((Path(tmp) / 'status.json').read_bytes())
        self.assertEqual(status['date'], '2026-11-21')
        self.assertEqual(status['safe_code'], 'minio_http_404')
        self.assertTrue(status['report_delayed'])
        objects.call.assert_called_once_with(
            'GET', 'receipts/20261121/pipeline-daily-20261121/checkpoint.json')
        objects.publish.assert_not_called()

    def test_old_batch_ready_is_verified_under_original_date_only(self):
        date, run_id = '2026-11-21', 'daily-20261121'
        prefix = 'receipts/20261121/pipeline-' + run_id
        base = dict(date=date, run_id=run_id, scope='three-repositories')
        commits = {repo: char * 40 for repo, char in zip(pipeline.REPOS, 'abc')}
        archives = {repo: dict(commit=commit) for repo, commit in commits.items()}
        checkpoints = {
            prefix + '/checkpoint.json': dict(
                base, prefix=prefix, archives=archives, commits=commits,
                published=True, publication_file_id='report-file'),
            prefix + '/components/checkpoint.json': dict(
                base, archives=archives, stages={'matrixflow_parse': {
                    'status': 'completed', 'execution_id': 'original-parse',
                    'parse_registration_recovery': {'attempts': 1}}}),
            prefix + '/reviews/checkpoint.json': dict(base, commits=commits),
        }
        objects = Mock()
        objects.call.side_effect = lambda method, key: (None, None, json.dumps(checkpoints[key]).encode())
        expected_clock = dt.datetime(2026, 11, 22, 0, 2, tzinfo=pipeline.preflight.LOCAL)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.env, clear=True), \
             patch.object(pipeline, 'Path', return_value=Path(tmp)), \
             patch.object(pipeline.dt, 'datetime', wraps=dt.datetime) as clock, \
             patch.object(pipeline, 'DailyAPI') as api, \
             patch.object(pipeline.preflight.Objects, 'from_workspace', return_value=objects), \
             patch.object(pipeline, 'verify_publication', return_value={'content_recovery': True}), \
             patch('daily_delivery.export_ready') as ready:
            clock.now.return_value = expected_clock
            self.assertEqual(pipeline.main(), 0)
            status = json.loads((Path(tmp) / 'status.json').read_bytes())
        ready.assert_called_once_with(api.return_value, objects, prefix, date)
        self.assertTrue(status['report_delayed'])
        self.assertFalse(status['sent'])
        self.assertFalse(status['kb_verified'])
        self.assertEqual({args[1] for args, _ in objects.call.call_args_list}, checkpoints.keys())
        objects.publish.assert_not_called()
