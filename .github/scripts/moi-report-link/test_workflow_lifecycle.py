import copy
import json
import types
import unittest
import uuid

from cloud_daily import Runner, WORKSPACE, Failure, sha256, json_bytes


class MemoryObjects:
    def __init__(self):
        self.files = {}
        self.fail = False

    def publish(self, key, raw, content_type):
        if self.fail:
            raise TimeoutError()
        self.files[key] = raw
        return dict(key=key, bytes=len(raw), sha256=sha256(raw), readback_verified=True)

    def call(self, method, key, **kw):
        return 200, {}, self.files[key]


class WorkflowAPI:
    def __init__(self):
        self.exists = False
        self.deploys = self.submits = self.deletes = 0
        self.raw = b'verified output'
        self.terminal = 'completed'
        self.lost_delete = False
        self.active = 0
        self.changed = False

    @staticmethod
    def data(value):
        return value

    def file(self, fid):
        if fid != 'file-1':
            raise AssertionError(fid)
        return self.raw

    def request(self, path, payload=None, method=None, **kw):
        if path.endswith('/workflow-deployments'):
            self.deploys += 1
            self.exists = True
            self.wid = payload['workflow_id']
            self.definition = dict(id=self.wid, name=payload['name'], description=payload['description'], execution_mode='one_shot')
            return {}
        if path.endswith('/executions'):
            self.submits += 1
            return {'workflow_run': {'execution_id': 'execution-1'}}
        if path.endswith('/result'):
            if not self.exists:
                raise Failure('moi_http_404')
            return {'result': dict(execution_id='execution-1', workflow_id=self.wid, status=self.terminal)}
        if '/nodes/root.' in path:
            if not self.exists:
                raise Failure('moi_http_404')
            return {'run': {'runtime_output': {'file_id': 'file-1'}}}
        if method == 'DELETE':
            self.deletes += 1
            self.exists = False
            if self.lost_delete:
                raise TimeoutError()
            return {}
        if not self.exists:
            raise Failure('moi_http_404')
        definition = dict(self.definition, execution_summary=dict(active_executions=self.active,
                          latest_execution_id='another-run' if self.changed else 'execution-1', total_executions=1))
        return {'workflow': definition}


class WorkflowLifecycleTests(unittest.TestCase):
    def runner(self):
        api, objects = WorkflowAPI(), MemoryObjects()
        value = dict(date='2026-10-26', scope='three-repositories', run_id='test-1', prefix='private/test-1')
        journal = types.SimpleNamespace(value=value, save=lambda: None)
        runner = Runner(api, objects, journal)
        runner.event = lambda **kw: None
        return runner, [runner.sink('output', 'verified output', 'test.txt', fmt='markdown')]

    def test_success_is_archived_deleted_and_resumes_without_execution(self):
        runner, nodes = self.runner()
        first = runner.workflow('lifecycle_probe', nodes)
        stage = runner.state['stages']['lifecycle_probe']
        self.assertEqual(stage['cleanup']['status'], 'deleted')
        archive = json.loads(runner.objects.files[stage['workflow_archive']['key']])
        self.assertEqual(archive['result']['status'], 'completed')
        self.assertEqual(archive['outputs']['output']['sha256'], sha256(runner.api.raw))
        self.assertEqual(runner.workflow('lifecycle_probe', nodes), first)
        self.assertEqual((runner.api.deploys, runner.api.submits, runner.api.deletes), (1, 1, 1))

    def uncertain_deployment(self, damage=None):
        runner, nodes = self.runner()
        original = runner.api.request
        definition = {}
        def request(path, payload=None, method=None, **kw):
            if path.endswith('/workflow-deployments'):
                original(path, payload, method, **kw)
                definition.update(runner.api.definition, dsl_yaml=payload['dsl_yaml'],
                                  source_type='manual_dsl', status='ready',
                                  execution_summary=dict(total_executions=0, active_executions=0))
                raise TimeoutError('lost deployment response')
            if (runner.state.get('stages', {}).get('lifecycle_probe', {}).get('status') == 'deploying'
                    and '/workflow-apps/' in path and '/executions' not in path):
                answer = copy.deepcopy(definition)
                if damage == 'dsl': answer['dsl_yaml'] += 'changed'
                if damage == 'active': answer['execution_summary']['active_executions'] = 1
                if damage == 'executed': answer['execution_summary']['total_executions'] = 1
                if damage == 'identity': answer['id'] = 'another-workflow'
                if damage == 'missing': raise Failure('moi_http_404')
                return dict(workflow=answer)
            return original(path, payload, method, **kw)
        runner.api.request = request
        with self.assertRaises(TimeoutError):
            runner.workflow('lifecycle_probe', nodes)
        return runner, nodes

    def test_lost_deployment_ack_recovers_exact_app_without_redeployment(self):
        runner, nodes = self.uncertain_deployment()
        runner.workflow('lifecycle_probe', nodes)
        self.assertTrue(runner.state['stages']['lifecycle_probe']['deployment_reconciled'])
        self.assertEqual((runner.api.deploys, runner.api.submits), (1, 1))

    def test_deployment_recovery_blocks_changed_missing_or_executed_app(self):
        for damage in ('dsl', 'active', 'executed', 'identity', 'missing'):
            with self.subTest(damage=damage):
                runner, nodes = self.uncertain_deployment(damage)
                with self.assertRaises(Failure):
                    runner.workflow('lifecycle_probe', nodes)
                self.assertEqual((runner.api.deploys, runner.api.submits), (1, 0))

    def test_next_batch_never_recreates_a_previously_deleted_app_id(self):
        runner, nodes = self.runner()
        runner.workflow('lifecycle_probe', nodes)
        old_id = runner.state['stages']['lifecycle_probe']['workflow_id']
        later, later_nodes = self.runner()
        later.state['run_id'] = 'test-2'
        later.state['prefix'] = 'private/test-2'
        later.workflow('lifecycle_probe', later_nodes)
        new_id = later.state['stages']['lifecycle_probe']['workflow_id']
        self.assertNotEqual(old_id, new_id)
        self.assertEqual(later.state['stages']['lifecycle_probe']['cleanup']['status'], 'deleted')

    def test_uncertain_delete_is_reconciled_without_second_delete(self):
        runner, nodes = self.runner()
        runner.api.lost_delete = True
        runner.workflow('lifecycle_probe', nodes)
        self.assertEqual(runner.state['stages']['lifecycle_probe']['cleanup']['status'], 'deleted')
        self.assertEqual(runner.api.deletes, 1)

    def test_backup_failure_retains_app_and_retry_uses_cached_output(self):
        runner, nodes = self.runner()
        runner.objects.fail = True
        runner.workflow('lifecycle_probe', nodes)
        stage = runner.state['stages']['lifecycle_probe']
        self.assertEqual(stage['cleanup']['status'], 'pending')
        self.assertTrue(runner.api.exists)
        self.assertEqual(runner.api.deletes, 0)
        runner.objects.fail = False
        runner.workflow('lifecycle_probe', nodes)
        self.assertEqual(stage['cleanup']['status'], 'deleted')
        self.assertEqual((runner.api.deploys, runner.api.submits), (1, 1))

    def test_active_or_superseded_app_is_never_deleted(self):
        for attribute in ('active', 'changed'):
            runner, nodes = self.runner()
            setattr(runner.api, attribute, 1)
            runner.workflow('lifecycle_probe', nodes)
            self.assertEqual(runner.api.deletes, 0)
            self.assertEqual(runner.state['stages']['lifecycle_probe']['cleanup']['status'], 'pending')

    def test_modified_cached_file_blocks_resume(self):
        runner, nodes = self.runner()
        runner.workflow('lifecycle_probe', nodes)
        runner.api.raw = b'tampered'
        with self.assertRaisesRegex(ValueError, 'cache_hash_mismatch'):
            runner.workflow('lifecycle_probe', nodes)
        self.assertEqual(runner.api.submits, 1)

    def test_changed_inputs_block_resume(self):
        runner, nodes = self.runner()
        runner.workflow('lifecycle_probe', nodes)
        changed = copy.deepcopy(nodes)
        changed[0]['input']['text'] = 'different input'
        with self.assertRaisesRegex(Failure, 'resume_input_changed'):
            runner.workflow('lifecycle_probe', changed)
        self.assertEqual(runner.api.submits, 1)

    def test_failed_execution_preserves_failure_without_resubmission(self):
        runner, nodes = self.runner()
        runner.api.terminal = 'failed'
        for _ in range(2):
            with self.assertRaisesRegex(Failure, 'moi_workflow_failed'):
                runner.workflow('lifecycle_probe', nodes)
        stage = runner.state['stages']['lifecycle_probe']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['cleanup']['status'], 'deleted')
        self.assertEqual((runner.api.deploys, runner.api.submits), (1, 1))

    def test_crash_after_delete_recovers_from_verified_archive(self):
        from workflow_lifecycle import retire
        runner, nodes = self.runner()
        runner.workflow('lifecycle_probe', nodes)
        stage = runner.state['stages']['lifecycle_probe']
        del stage['cleanup']
        retire(runner, 'lifecycle_probe')
        self.assertEqual(stage['cleanup']['status'], 'deleted')
        self.assertEqual(runner.api.deletes, 1)

    def test_unowned_id_and_missing_output_cache_block_cleanup(self):
        from workflow_lifecycle import retire
        for damage in ('workflow_id', 'output_artifacts'):
            runner, nodes = self.runner()
            runner.api.active = 1
            runner.workflow('lifecycle_probe', nodes)
            stage = runner.state['stages']['lifecycle_probe']
            runner.api.active = 0
            if damage == 'workflow_id':
                stage[damage] = str(uuid.uuid4())
            else:
                del stage[damage]
            retire(runner, 'lifecycle_probe')
            self.assertEqual(runner.api.deletes, 0)

