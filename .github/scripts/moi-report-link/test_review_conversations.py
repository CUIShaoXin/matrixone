import copy
import hashlib
import unittest
from unittest.mock import patch

from cloud_daily import AGENT, WORKSPACE
from review_conversations import run_isolated_review
from test_pipeline_recovery import Job, Model


class API(Model):
    def __init__(self):
        super().__init__([])
        self.conversations, self.posts = {}, []
        self.lost_create = self.lost_send = self.wrong_parent = False
        self.fail_auth = False

    @staticmethod
    def data(value): return value

    def request(self, path, payload=None, method=None, **kwargs):
        if method == 'POST':
            self.posts.append(copy.deepcopy(payload))
            value = dict(payload, workspace_id=WORKSPACE, status='active',
                         parent_conversation_id='other' if self.wrong_parent else '')
            self.conversations[payload['id']] = value
            if self.lost_create: raise TimeoutError()
            return value
        cid = path.split('?')[0].split('/')[-1]
        if cid not in self.conversations: raise ValueError('conversation_missing')
        return copy.deepcopy(self.conversations[cid])

    def rpc(self, method, params, rid):
        self.requests.append((method, copy.deepcopy(params), rid))
        if method == 'message/send':
            suffix = hashlib.sha256((WORKSPACE+'\x00'+rid).encode()).hexdigest()[:48]
            self.task = dict(id='art-'+suffix, status=dict(state='failed' if self.fail_auth else 'completed'),
                             metadata=dict(manifestId='arm-'+suffix,
                                reason_display=dict(i18n_key='reason.agent_runtime.authorization_failed')))
            if self.lost_send: raise TimeoutError()
        return copy.deepcopy(self.task)


class RootConversationTests(unittest.TestCase):
    def job(self):
        api = API(); job = Job(api)
        job.state['date'] = '2026-11-05'; job.objects = object()
        return api, job

    def run_model(self, job):
        return run_isolated_review(job, 'repo', 'primary', 'source', 'prompt',
                                   lambda t:t['id'], poll_seconds=0)

    def test_explicit_root_and_immutable_exact_request_are_used(self):
        api, job = self.job()
        with patch('daily_delivery.create_once', side_effect=lambda o,k,p:(True,p)):
            self.run_model(job)
        self.assertEqual(len(api.posts),1)
        self.assertNotIn('parent_conversation_id',api.posts[0])
        sent = api.requests[0][1]
        self.assertEqual(sent['message']['contextId'],api.posts[0]['id'])
        self.assertEqual(job.stored['repo/primary/attempt-1-request.json'],sent)
        self.assertTrue(job.state['model_tasks']['repo_primary']['attempts'][0]['submission_reserved'])

    def test_lost_creation_ack_is_read_back_without_second_post(self):
        api, job = self.job(); api.lost_create=True
        with patch('daily_delivery.create_once', side_effect=lambda o,k,p:(True,p)):
            self.run_model(job)
        self.assertEqual(len(api.posts),1)
        self.assertEqual([r[0] for r in api.requests],['message/send'])

    def test_wrong_parent_never_submits_model(self):
        api, job = self.job(); api.wrong_parent=True
        with patch('daily_delivery.create_once', side_effect=lambda o,k,p:(True,p)):
            with self.assertRaisesRegex(ValueError,'not_parentless'):
                self.run_model(job)
        self.assertEqual(api.requests,[])

    def test_lost_send_ack_only_reads_original_task(self):
        api, job = self.job(); api.lost_send=True
        with patch('daily_delivery.create_once', side_effect=lambda o,k,p:(True,p)):
            self.run_model(job)
        self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])
        self.assertEqual(len(api.posts),1)

    def test_auth_failure_is_preserved_and_not_retried(self):
        api, job = self.job(); api.fail_auth=True
        with patch('daily_delivery.create_once', side_effect=lambda o,k,p:(True,p)):
            with self.assertRaisesRegex(ValueError,'nonrecoverable'):self.run_model(job)
            with self.assertRaisesRegex(ValueError,'nonrecoverable'):self.run_model(job)
        self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])
        self.assertEqual(len(api.posts),1)

    def test_reservation_uncertain_blocks_without_post_or_resubmission(self):
        api, job = self.job()
        with patch('daily_delivery.create_once', side_effect=TimeoutError()):
            with self.assertRaisesRegex(ValueError,'conversation_missing'):self.run_model(job)
        # No task was submitted. Restart remains read-only, never a second POST.
        with patch('daily_delivery.create_once') as create:
            with self.assertRaisesRegex(ValueError,'conversation_missing'):self.run_model(job)
        create.assert_not_called();self.assertEqual(api.posts,[])
        self.assertTrue(all(r[0]=='tasks/get' for r in api.requests))

    def test_existing_reservation_is_read_only_and_conflict_blocks(self):
        api, job = self.job()
        with patch('daily_delivery.create_once',side_effect=lambda o,k,p:(False,dict(p,phase='other'))):
            with self.assertRaisesRegex(ValueError,'reservation_conflict'):self.run_model(job)
        self.assertEqual(api.posts,[])

    def test_evidence_write_failure_before_inference_resumes_original_root(self):
        api,job=self.job();original_store=job.store;failed=[False]
        def store(name,value):
            if name.endswith('-conversation.json') and not failed[0]:
                failed[0]=True
                raise ValueError('evidence_write_failed')
            return original_store(name,value)
        job.store=store
        with patch('daily_delivery.create_once',side_effect=lambda o,k,p:(True,p)):
            with self.assertRaisesRegex(ValueError,'evidence_write_failed'):self.run_model(job)
        self.assertEqual(api.requests,[]);self.assertEqual(len(api.posts),1)
        with patch('daily_delivery.create_once') as create:
            self.run_model(job)
        create.assert_not_called();self.assertEqual(len(api.posts),1)
        self.assertEqual([r[0] for r in api.requests],['message/send'])

    def test_pre_submission_restart_does_not_refresh_expired_inference_budget(self):
        api,job=self.job();original_store=job.store
        def store(name,value):
            if name.endswith('-conversation.json'):raise ValueError('evidence_write_failed')
            return original_store(name,value)
        job.store=store
        with patch('daily_delivery.create_once',side_effect=lambda o,k,p:(True,p)):
            with self.assertRaisesRegex(ValueError,'evidence_write_failed'):self.run_model(job)
        job.state['model_tasks']['repo_primary']['started_epoch']=0
        with self.assertRaisesRegex(ValueError,'deadline_exceeded'):self.run_model(job)
        self.assertEqual(api.requests,[]);self.assertEqual(len(api.posts),1)

    def test_completed_legacy_task_keeps_original_context_and_no_conversation_create(self):
        api, job = self.job()
        from kimi_recovery import run_review
        run_review(job,'repo','primary','source','prompt',lambda t:t['id'],poll_seconds=0)
        before=copy.deepcopy(job.state['model_tasks']['repo_primary'])
        with patch('daily_delivery.create_once') as create:
            self.run_model(job)
        create.assert_not_called();self.assertEqual(len(api.posts),0)
        self.assertEqual(job.state['model_tasks']['repo_primary']['task_id'],before['task_id'])


if __name__ == '__main__': unittest.main()
