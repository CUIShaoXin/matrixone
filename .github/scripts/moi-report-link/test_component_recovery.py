"""Pipeline-entry recovery with real ZIPs, original scan/acceptance and fake MOI IO."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import cloud_daily
import daily_pipeline as pipeline
import orchestration_status
from batch_context import BatchContext
from test_orchestration_recovery import MemoryObjects
from workflow_lifecycle import cached_outputs


class ArtifactAPI:
    def __init__(self):
        self.files = {}

    def upload(self, name, raw):
        fid = 'file-'+str(len(self.files)+1)
        self.files[fid] = raw
        return cloud_daily.file_evidence(fid, raw, name=name)

    def file(self, fid):
        return self.files[fid]

    def rpc(self, *args):
        raise AssertionError('Unexpected inference or message send')


class FixedGitHub:
    token = 'in-memory-test'

    def __init__(self):
        self.commit = 'a'*40
        self.requests = []
        self.archives = {}

    def get(self, repo, path, binary=False):
        self.requests.append((repo, path))
        if path.startswith('/branches/'):
            return dict(commit=dict(sha=self.commit))
        if path not in self.archives:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.comment = path.rsplit('/', 1)[-1].encode()
                archive.writestr('repo-root/go.mod', 'module example.test/repo\ngo 1.24\n')
            self.archives[path] = stream.getvalue()
        return self.archives[path]


class WorkflowIO:
    """Remote workflow boundary; cached artifacts retain the production hash checks."""
    def __init__(self, api):
        self.api = api
        self.executed = []
        self.generated = {}
        self.bad_labels = {'taas_finalize'}
        self.interrupt_label = None
        self.timeout_label = None

    def workflow(self, runner, label, nodes):
        stages = runner.state.setdefault('stages', {})
        stage = stages.get(label)
        digest = cloud_daily.sha256(cloud_daily.json_bytes(nodes))
        if stage:
            cloud_daily.require(stage['input_sha256'] == digest, 'workflow_resume_input_changed')
            if stage['status'] == 'submitting':
                raise cloud_daily.Failure('workflow_execution_uncertain_do_not_resubmit')
            return cached_outputs(runner, stage, nodes)
        if label == self.interrupt_label:
            self.interrupt_label = None
            raise KeyboardInterrupt()
        self.executed.append(label)
        stage = stages[label] = dict(status='submitting', input_sha256=digest,
            workflow_id='workflow-'+label, execution_id='execution-'+label)
        runner.journal.save()
        if label == self.timeout_label:
            raise TimeoutError()
        repo = label.split('_', 1)[0]
        if label.endswith('_parse'):
            outputs = dict(parsed=b'{"coordinates":[]}')
        elif '_finalize' in label:
            proof = runner.state['archives'][repo]
            marker = 'MATRIX-'+repo+'-'+proof['commit']
            facts = dict(report_date_shanghai=runner.state['date'], marker=marker,
                scope=cloud_daily.IMPORT_DESCRIPTION+'; supported exact declared/locked versions only; no installed dependency resolution',
                complete_details_entry='MinIO browser report published only after independent acceptance',
                **{key: 0 for key in cloud_daily.COUNTS})
            osv = dict(status='declared_version_queries_completed', commit=proof['commit'],
                facts=facts, manifest_integrity_verified=True, source_commit_verified=True,
                execution_location='MOI cloud Python worker',
                report_presentation_normalized_by='GitHub Actions cloud runner; scan results unchanged')
            outputs = dict(osv=cloud_daily.json_bytes(osv), details=(marker+'-DETAIL').encode(),
                employee_report=b'Incomplete generation' if label in self.bad_labels else (marker+'-EMPLOYEE').encode(),
                validation=b'{"accepted":true}')
            self.generated[repo] = outputs
        elif label.endswith('_store_accepted_v4'):
            source = self.generated[repo]
            outputs = dict(osv=source['osv'], details=source['details'], employee=source['employee_report'])
        elif label.endswith('_compact_evidence_index'):
            outputs = dict(index=nodes[0]['input']['text'].encode())
        else:
            raise AssertionError(label)
        result = {}
        for node in nodes:
            if node['id'] == 'moi:catalog.sink.write':
                raw = outputs[node['name']]
                result[node['name']] = (self.api.upload(node['input']['output_file_name'], raw), raw)
        stage.update(status='completed', output_artifacts={name:item[0] for name,item in result.items()})
        runner.journal.save()
        return result


class ComponentRecoveryEntryTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        previous = os.getcwd()
        os.chdir(tmp)
        self.stack.callback(os.chdir, previous)
        self.api, self.store, self.github = ArtifactAPI(), MemoryObjects(), FixedGitHub()
        self.workflows = WorkflowIO(self.api)
        self.publications = []
        self.review_inferences = []
        self.env = dict(MATRIX_PIPELINE_RUN_ID='moi-recovery-entry', MATRIX_BUSINESS_DATE='2026-10-27',
            MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_EXECUTION_MODE='no_send', MATRIX_PIPELINE_MODE='full',
            GITHUB_RUN_ID='900', GITHUB_RUN_ATTEMPT='1', MOI_API_KEY='memory', SCAN_GITHUB_TOKEN='memory')
        self.stack.enter_context(patch.dict(os.environ, self.env, clear=True))
        self.stack.enter_context(patch.object(pipeline, 'DailyAPI', return_value=self.api))
        self.stack.enter_context(patch.object(pipeline.preflight.Objects, 'from_workspace', return_value=self.store))
        self.stack.enter_context(patch.object(pipeline.preflight, 'GitHub', return_value=self.github))
        self.stack.enter_context(patch('archive_transfer.tempfile.gettempdir', return_value=tmp))
        backend = self.workflows
        self.stack.enter_context(patch.object(cloud_daily.Runner, 'workflow',
            lambda runner, label, nodes: backend.workflow(runner, label, nodes)))
        def knowledge(runner, tag, saved, targets):
            saved['rag_proof'] = [dict(file_id=t['file_id'], marker=t['marker']) for t in targets]
            runner.journal.save()
        self.stack.enter_context(patch.object(cloud_daily.Runner, 'knowledge', knowledge))
        self.stack.enter_context(patch.object(pipeline, 'code_review',
            side_effect=lambda job, repo, proof: self.review(job, repo, proof, 'code_repositories')))
        self.stack.enter_context(patch.object(pipeline, 'api_review',
            side_effect=lambda job, repo, proof: self.review(job, repo, proof, 'repositories')))
        self.stack.enter_context(patch.object(pipeline, 'build_focus', return_value=[]))
        self.stack.enter_context(patch.object(pipeline, 'publish_report', side_effect=self.publish))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.ctx = BatchContext.from_env()

    def review(self, job, repo, proof, field):
        saved = job.state.setdefault(field, {}).setdefault(repo, {})
        if saved.get('accepted'):
            return saved['value']
        self.review_inferences.append((field, repo, proof['commit']))
        result = dict(commit=proof['commit'], retained_findings=[], selected_files=0, selected_lines=0)
        saved.update(accepted=True, value=result)
        job.journal.save()
        return result

    def publish(self, job, source, page, api_results):
        self.publications.append(source)
        return dict(receipt_artifact=self.api.upload('publication.json', b'{}'), added_findings=0)

    def checkpoint(self, suffix):
        return json.loads(self.store.data[self.ctx.prefix+'/'+suffix])

    def seed_original_failure(self):
        with patch.object(pipeline, 'Runner',
                lambda api, objects, journal, **kwargs: cloud_daily.Runner(api, objects, journal)):
            self.assertEqual(pipeline.main(), 1)
        status = json.loads(Path('out/pipeline/status.json').read_bytes())
        self.assertEqual(status['safe_code'], 'component_scan_incomplete')
        root = self.checkpoint('checkpoint.json')
        self.assertIn(dict(stage='components', repository='taas', safe_code='employee_marker_missing'),
            [{key:f[key] for key in ('stage', 'repository', 'safe_code') if key in f} for f in root['failures']])
        self.assertEqual(self.publications, [])

    def test_entry_recovers_rejected_output_without_changing_commits_or_successful_stages(self):
        self.seed_original_failure()
        original = self.checkpoint('components/checkpoint.json')
        rejected = original['stages']['taas_finalize']['output_artifacts']['employee_report']
        self.github.commit = 'b'*40
        self.github.requests.clear()
        self.workflows.executed.clear()
        self.review_inferences.clear()
        os.environ['GITHUB_RUN_ATTEMPT'] = '2'
        self.assertEqual(pipeline.main(), 0)
        self.assertEqual(self.github.requests, [])
        self.assertEqual(self.review_inferences, [])
        self.assertEqual(self.workflows.executed,
            ['taas_finalize_recovery_2', 'taas_store_accepted_v4', 'taas_compact_evidence_index'])
        current = self.checkpoint('components/checkpoint.json')
        self.assertEqual(current['stages']['taas_finalize'], original['stages']['taas_finalize'])
        self.assertEqual(self.api.file(rejected['file_id']), b'Incomplete generation')
        self.assertTrue(current['repositories']['taas']['accepted'])
        self.assertEqual(self.publications[0]['commits'], dict.fromkeys(('matrixone', 'taas', 'matrixflow'), 'a'*40))
        status = orchestration_status.snapshot(self.api, self.store, BatchContext.from_env())
        taas = status['repositories']['taas']
        self.assertEqual(taas['stages']['component_scan'], 'succeeded')
        self.assertEqual(taas['component_retry_count'], 1)
        self.assertEqual([(a['label'], a['validation']) for a in taas['component_attempts']],
            [('taas_finalize', 'rejected'), ('taas_finalize_recovery_2', 'accepted')])
        self.assertEqual(taas['component_attempts'][0]['failure']['code'], 'employee_marker_missing')
        self.assertEqual(taas['component_attempts'][1]['github'], dict(run_id='900', attempt=2))
        self.assertFalse(status['sent'])

    def test_repeated_bad_outputs_keep_bounded_attempts_across_entry_restarts(self):
        self.workflows.bad_labels.update({'taas_finalize_recovery_2', 'taas_finalize_recovery_3'})
        self.assertEqual(pipeline.main(), 1)
        completed = list(self.workflows.executed)
        self.assertEqual(pipeline.main(), 1)
        self.assertEqual(self.workflows.executed, completed)
        state = self.checkpoint('components/checkpoint.json')
        attempts = state['workflow_recovery']['taas_finalize']['attempts']
        self.assertEqual([(a['label'], a['validation']) for a in attempts], [
            ('taas_finalize', 'rejected'), ('taas_finalize_recovery_2', 'rejected'),
            ('taas_finalize_recovery_3', 'rejected')])
        self.assertFalse(state['repositories']['taas'].get('accepted', False))
        self.assertEqual(self.publications, [])

    def test_uncertain_workflow_submission_does_not_start_another_attempt(self):
        self.workflows.timeout_label = 'taas_finalize'
        self.assertEqual(pipeline.main(), 1)
        submitted = list(self.workflows.executed)
        self.assertEqual(pipeline.main(), 1)
        self.assertEqual(self.workflows.executed, submitted)
        state = self.checkpoint('components/checkpoint.json')
        self.assertEqual(state['stages']['taas_finalize']['status'], 'submitting')
        self.assertNotIn('taas_finalize_recovery_2', state['stages'])
        self.assertEqual(self.publications, [])

    def test_crash_before_retry_execution_resumes_the_persisted_attempt_identity(self):
        self.seed_original_failure()
        self.workflows.interrupt_label = 'taas_finalize_recovery_2'
        with self.assertRaises(KeyboardInterrupt):
            pipeline.main()
        state = self.checkpoint('components/checkpoint.json')
        planned = state['workflow_recovery']['taas_finalize']['attempts'][-1]
        self.assertEqual((planned['label'], planned['validation']), ('taas_finalize_recovery_2', 'pending'))
        self.workflows.executed.clear()
        self.assertEqual(pipeline.main(), 0)
        self.assertEqual(self.workflows.executed,
            ['taas_finalize_recovery_2', 'taas_store_accepted_v4', 'taas_compact_evidence_index'])

    def test_corrupted_rejected_artifact_blocks_recovery_before_new_execution(self):
        self.seed_original_failure()
        state = self.checkpoint('components/checkpoint.json')
        fid = state['stages']['taas_finalize']['output_artifacts']['employee_report']['file_id']
        self.api.files[fid] = b'tampered evidence'
        self.workflows.executed.clear()
        self.assertEqual(pipeline.main(), 1)
        self.assertEqual(self.workflows.executed, [])
        self.assertEqual(self.publications, [])

    def test_changed_finalize_inputs_cannot_bypass_the_original_resume_contract(self):
        self.seed_original_failure()
        state = self.checkpoint('components/checkpoint.json')
        source = state['repositories']['taas']['final_sources'][0]
        source['file_id'] = self.api.upload('replacement-source.json', self.api.file(source['file_id']))['file_id']
        self.store.publish(self.ctx.prefix+'/components/checkpoint.json',
            cloud_daily.json_bytes(state), 'application/json')
        self.workflows.executed.clear()
        self.assertEqual(pipeline.main(), 1)
        self.assertEqual(self.workflows.executed, [])
        current = self.checkpoint('components/checkpoint.json')
        self.assertEqual(current['repositories']['taas']['scan_failure']['code'], 'workflow_resume_input_changed')
        self.assertNotIn('taas_finalize_recovery_2', current['stages'])
        self.assertEqual(self.publications, [])


if __name__ == '__main__':
    unittest.main()
