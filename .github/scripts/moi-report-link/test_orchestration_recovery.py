"""Failure-injection regressions at acquisition and snapshot entry boundaries."""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import zipfile

import archive_transfer
from batch_context import BatchContext
import orchestration_status


class MemoryObjects:
    def __init__(self): self.data = {}
    def call(self, method, key, **kwargs):
        if key not in self.data: raise RuntimeError('minio_http_404')
        return 200, {}, self.data[key]
    def publish(self, key, raw, kind): self.data[key] = raw
    def verify_object(self, key, size, digest):
        raw = self.data.get(key)
        return raw is not None and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest
    def put_verified(self, key, raw, digest, transfer, save):
        self.data[key] = raw
        if not self.verify_object(key, len(raw), digest): raise ValueError('minio_readback_mismatch')
        save()


def context():
    return BatchContext.from_env(dict(MATRIX_PIPELINE_RUN_ID='moi-recovery', MATRIX_BUSINESS_DATE='2026-10-27',
        MATRIX_TRIGGER_SOURCE='moi_api', MATRIX_EXECUTION_MODE='no_send'))


class SnapshotOutageTests(unittest.TestCase):
    def test_report_read_outage_does_not_lose_durable_final_status(self):
        ctx, store, api = context(), MemoryObjects(), Mock()
        store.publish(ctx.prefix+'/checkpoint.json', json.dumps(dict(published=True, publication_file_id='report')).encode(), 'application/json')
        api.file.side_effect = TimeoutError('private request URL must not be exposed')
        api.upload.side_effect = TimeoutError()
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            try:
                os.chdir(tmp)
                out = Path('out/orchestration'); out.mkdir(parents=True)
                (out/'status.json').write_text(json.dumps(dict(ctx.record(), status='succeeded', sent=False)))
                with self.assertRaises(TimeoutError): orchestration_status.sync(api, store, ctx)
            finally: os.chdir(previous)
        saved = json.loads(store.data[ctx.prefix+'/orchestration/status.json'])
        self.assertEqual(saved['status'], 'succeeded')
        self.assertEqual(saved['report_details'], dict(status='pending', error_type='TimeoutError'))
        self.assertEqual(saved['publication_file_id'], 'report')
        self.assertNotIn('private request URL', json.dumps(saved))

    def test_replay_fills_report_details_after_moi_recovers_without_business_execution(self):
        ctx, store, api = context(), MemoryObjects(), Mock()
        saved = dict(ctx.record(), status='succeeded', publication_file_id='report',
                     report_details=dict(status='pending', error_type='TimeoutError'))
        store.publish(ctx.prefix+'/orchestration/status.json', json.dumps(saved).encode(), 'application/json')
        api.upload.return_value = dict(file_id='status-file')
        def read(fid):
            if fid == 'report': return json.dumps(dict(url='https://reports.example.test/report', expires_at_utc='2026-11-03T00:00:00Z')).encode()
            if fid == 'status-file': return api.upload.call_args.args[1]
            raise AssertionError(fid)
        api.file.side_effect = read
        result = orchestration_status.upload_saved(api, store, ctx)
        published = json.loads(store.data[ctx.prefix+'/orchestration/status.json'])
        self.assertEqual(published['report_url'], 'https://reports.example.test/report')
        self.assertEqual(published['report_details']['status'], 'succeeded')
        self.assertTrue(result['synced'])
        api.rpc.assert_not_called()

    def test_unknown_delivery_is_not_presented_as_confirmed_not_sent(self):
        ctx, store = context(), MemoryObjects()
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            try:
                os.chdir(tmp)
                out = Path('out/orchestration'); out.mkdir(parents=True)
                (out/'status.json').write_text(json.dumps(dict(ctx.record(), status='failed', sent=None, failure_stage='delivery')))
                result = orchestration_status.snapshot(Mock(), store, ctx)
            finally: os.chdir(previous)
        self.assertIsNone(result['sent'])


class AcquisitionIsolationTests(unittest.TestCase):
    def zip_bytes(self, commit):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.comment = commit.encode()
            archive.writestr('repo-root/go.mod', 'module test\ngo 1.24\n')
        return stream.getvalue()

    def test_another_batch_cache_cannot_replace_this_batch_download(self):
        from cloud_preflight import validate_zip
        commit = 'a'*40
        raw = self.zip_bytes(commit)
        github = Mock()
        github.get.side_effect = [{'commit':{'sha':commit}}, raw]
        repo = types.SimpleNamespace(owner='matrixorigin', name='matrixone', branch='main')
        store = MemoryObjects()
        with tempfile.TemporaryDirectory() as tmp, patch.object(archive_transfer.tempfile, 'gettempdir', return_value=tmp):
            old_cache = Path(tmp)/'matrix-archive-cache'/('matrixorigin-matrixone-'+commit)
            old_cache.parent.mkdir()
            old_cache.write_bytes(raw)
            proof = archive_transfer.prepare(github, store, repo, 'new-batch', '2026-10-27', validate_zip, ValueError)
        self.assertEqual(github.get.call_args_list[-1].args, ('matrixorigin/matrixone', '/zipball/'+commit))
        self.assertTrue(github.get.call_args_list[-1].kwargs['binary'])
        self.assertEqual(proof['commit'], commit)
        self.assertTrue(store.verify_object(proof['key'], proof['bytes'], proof['sha256']))


if __name__ == '__main__': unittest.main()
