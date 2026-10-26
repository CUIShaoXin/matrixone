import copy
import datetime as dt
import unittest
from unittest.mock import Mock, patch

import daily_delivery as d


class DeliveryTests(unittest.TestCase):
    def bundle(self):
        codes = {r: dict(retained_findings=[]) for r in d.REPOS}
        apis = {r: dict(findings=[]) for r in d.REPOS}
        focus = [dict(repo=r, label='x/crypto', risk='受影响路径可能绕过验证，先核实使用条件。') for r in d.REPOS]
        codes['matrixflow']['retained_findings'] = [dict(title='角色恢复时可能重授权限')]
        apis['taas']['findings'] = [dict(title='调试监听配置需要核实')]
        return dict(source=dict(component_focus=focus, code_review=dict(repositories=codes)),
                    api_results=apis, pages_verified=4, root=dict(publication_file_id='file'),
                    publication_sha256='hash', receipt=dict(url='https://example.test/report?signature=long', expires_at_utc='2026-11-02T05:18:37+00:00'))

    def claim(self):
        return dict(date='2026-10-26', channel_instance_id=d.CHANNEL, task_id='task',
                    content=d.compose(self.bundle(), '2026-10-26'), attempt_id='attempt',
                    prefix='prefix', publication_file_id='file')

    def task(self):
        c = self.claim()
        return dict(id='task', status=dict(state='completed'), events=[
            dict(type='moi.tool.call', toolId='moi_wecom_robot_message', callId='call',
                 arguments=dict(channel_instance_id=d.CHANNEL, msg_type='markdown', content=c['content'])),
            dict(type='moi.tool.result', toolId='moi_wecom_robot_message', callId='call',
                 output=dict(output=dict(ok=True, status='COMPLETED', data=dict(ok=True), request_id='call')))])

    def test_compact_message_lists_all_three_scopes_and_hides_long_link(self):
        text = d.compose(self.bundle(), '2026-10-26')
        self.assertLessEqual(len(text.encode()), 4096)
        for r in d.REPOS: self.assertIn(d.NAMES[r], text)
        for s in ('角色恢复时可能重授权限', '调试监听配置需要核实', 'x/crypto', '[查看完整日报（免登录）]('): self.assertIn(s, text)
        self.assertNotIn('<a', text)

    def test_real_tool_output_required(self):
        self.assertTrue(d.verify_send(self.task(), self.claim())['sent'])
        task = self.task(); task['events'][1]['output']['output']['data']['ok'] = False
        with self.assertRaisesRegex(ValueError, 'real_tool_receipt'): d.verify_send(task, self.claim())

    def test_wrong_group_wrong_content_and_duplicate_tool_rejected(self):
        for field, value in [('channel_instance_id', 'other'), ('content', 'changed')]:
            task = self.task(); task['events'][0]['arguments'][field] = value
            with self.assertRaises(ValueError): d.verify_send(task, self.claim())
        task = self.task(); task['events'].append(dict(task['events'][0], callId='second'))
        with self.assertRaisesRegex(ValueError, 'invocation_count'): d.verify_send(task, self.claim())

    def test_old_ready_and_changed_publication_block_before_send(self):
        api, objects = Mock(), Mock()
        for pointer in (dict(schema='matrix_daily_ready_v1', date='2026-10-25', scope='three-repositories'),
                        dict(schema='matrix_daily_ready_v1', date='2026-10-26', scope='three-repositories', prefix='prefix', publication_file_id='other', publication_sha256='hash')):
            with patch.object(d, 'read_json', side_effect=[None, pointer]), patch.object(d, 'check_bundle', return_value=self.bundle()):
                with self.assertRaises(ValueError): d.deliver(api, objects, '2026-10-26')
            api.rpc.assert_not_called()

    def test_preview_checks_but_never_claims_or_sends(self):
        api, objects = Mock(), Mock()
        pointer = dict(schema='matrix_daily_ready_v1', date='2026-10-26', scope='three-repositories', prefix='prefix', publication_file_id='file', publication_sha256='hash')
        with patch.object(d, 'read_json', side_effect=[None, pointer]), patch.object(d, 'check_bundle', return_value=self.bundle()), patch.object(d, 'create_once') as create:
            self.assertEqual(d.deliver(api, objects, '2026-10-26', preview=True)['status'], 'preview_passed')
            create.assert_not_called(); api.rpc.assert_not_called()

    def test_second_trigger_only_reads_original_task(self):
        api, objects = Mock(), Mock(); api.rpc.return_value = self.task()
        final = d.verify_send(self.task(), self.claim())
        with patch.object(d, 'read_json', side_effect=[final, self.claim()]), patch.object(d, 'native_receipt', return_value=dict(file_id='receipt')):
            result = d.deliver(api, objects, '2026-10-26')
        self.assertTrue(result['duplicate_prevented'])
        self.assertEqual([c.args[0] for c in api.rpc.call_args_list], ['tasks/get'])

    def test_existing_claim_and_unknown_task_never_resubmits(self):
        api, objects = Mock(), Mock(); api.rpc.return_value = dict(id='task', status=dict(state='input-required'))
        pointer = dict(schema='matrix_daily_ready_v1', date='2026-10-26', scope='three-repositories', prefix='prefix', publication_file_id='file', publication_sha256='hash')
        with patch.object(d, 'read_json', side_effect=[None, pointer, self.claim()]), patch.object(d, 'check_bundle', return_value=self.bundle()):
            with self.assertRaisesRegex(ValueError, 'terminal_do_not_resend'): d.deliver(api, objects, '2026-10-26')
        self.assertEqual([c.args[0] for c in api.rpc.call_args_list], ['tasks/get'])

    def test_atomic_write_uses_condition_and_never_overwrites_winner(self):
        objects = Mock(); value = dict(owner='first'); objects.call.return_value = (200, {}, d.json_bytes(value))
        with patch.object(d.SignedObjects, 'call') as put:
            self.assertEqual(d.create_once(objects, 'claim', value), (True, value))
            self.assertEqual(put.call_args.args[4]['if-none-match'], '*')
        with patch.object(d.SignedObjects, 'call', side_effect=RuntimeError('minio_http_412')) as put, patch.object(d, 'read_json', return_value=value):
            self.assertEqual(d.create_once(objects, 'claim', dict(owner='second')), (False, value))
            self.assertEqual(put.call_count, 1)

    def test_atomic_write_timeout_never_retries_or_grants_send(self):
        with patch.object(d.SignedObjects, 'call', side_effect=TimeoutError) as put:
            with self.assertRaises(TimeoutError): d.create_once(Mock(), 'claim', {})
            self.assertEqual(put.call_count, 1)

    def test_batch_prefix_cannot_reference_yesterday(self):
        with self.assertRaisesRegex(ValueError, 'prefix_invalid'):
            d.check_bundle(Mock(), Mock(), 'receipts/20261025/pipeline-old', '2026-10-26')


if __name__ == '__main__': unittest.main()
