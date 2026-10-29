import copy, json, types, unittest
from unittest.mock import patch
from cloud_daily import Runner, Failure, file_evidence, sha256


class ManifestRecoveryTests(unittest.TestCase):
    def fixture(self, count=2):
        bodies = {f'dir/{i}.mod': f'manifest-{i}'.encode() for i in range(count)}
        entries = [dict(path=k, bytes=len(v), sha256=sha256(v)) for k, v in bodies.items()]
        saved = dict(manifests=[])
        self.snapshots = []
        journal = types.SimpleNamespace(value=dict(run_id='daily-20261029'), save=lambda: self.snapshots.append(copy.deepcopy(saved)))
        self.files = {}; self.mounted = {}; self.uploads = 0; self.attaches = 0
        def request(path, payload=None, **kwargs):
            if path == '/catalog/file/list':
                name = payload['filters'][1]['values'][0]
                rows = [dict(name=name, volume_id='130001', id=self.mounted[name])] if name in self.mounted else []
                return dict(total=len(rows), list=rows)
            if path == '/catalog/file/create':
                self.attaches += 1
                fid = payload['file_ids'][0]
                self.mounted[self.files[fid][0]] = fid
                return {}
            raise AssertionError(path)
        def binary(path, raw=None, **kwargs):
            self.assertEqual(path, '/catalog/file/upload')
            self.uploads += 1
            name = raw.split(b'filename="')[1].split(b'"')[0].decode()
            body = raw.split(b'\r\n\r\n', 1)[1].rsplit(b'\r\n--', 1)[0]
            fid = f'file-{self.uploads}'
            self.files[fid] = (name, body)
            return json.dumps(dict(code='OK', data=dict(file_id=fid))).encode()
        api = types.SimpleNamespace(request=request, binary=binary, data=lambda x:x,
                                    file=lambda fid:self.files[fid][1])
        objects = types.SimpleNamespace(call=lambda *a, **kw:(200, {}, b'zip'))
        return Runner(api, objects, journal), types.SimpleNamespace(name='matrixone'), dict(key='fixed.zip', bytes=3, manifests=entries), saved, bodies

    def test_empty_legacy_import_is_resumed_and_each_file_persisted(self):
        runner, repo, proof, saved, bodies = self.fixture()
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            result = runner.import_manifests(repo, proof, saved)
        self.assertEqual(len(result), 2)
        self.assertTrue(saved['manifest_import_complete'])
        self.assertEqual((self.uploads, self.attaches), (2,2))
        self.assertTrue(any(len(s['manifests']) == 1 for s in self.snapshots))
        self.assertNotIn('manifest_upload_pending', saved)

    def test_partial_prefix_and_previously_attached_file_are_reused(self):
        runner, repo, proof, saved, bodies = self.fixture()
        self.files['old-0'] = ('matrixone-daily-20261029-manifest-0.txt', bodies['dir/0.mod'])
        self.files['old-1'] = ('matrixone-daily-20261029-manifest-1.txt', bodies['dir/1.mod'])
        saved['manifests'] = [dict(file_evidence('old-0', bodies['dir/0.mod']), path='dir/0.mod')]
        self.mounted['matrixone-daily-20261029-manifest-1.txt'] = 'old-1'
        saved['manifest_upload_pending'] = dict(name='matrixone-daily-20261029-manifest-1.txt', path='dir/1.mod', sha256=sha256(bodies['dir/1.mod']), attach_attempted=True)
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            runner.import_manifests(repo, proof, saved)
        self.assertEqual((self.uploads, self.attaches), (0,0))
        self.assertEqual([x['file_id'] for x in saved['manifests']], ['old-0','old-1'])

    def test_lost_upload_response_blocks_reupload(self):
        runner, repo, proof, saved, bodies = self.fixture(1)
        saved['manifest_upload_pending'] = dict(name='matrixone-daily-20261029-manifest-0.txt', path='dir/0.mod', sha256=sha256(bodies['dir/0.mod']), status='upload_unknown')
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            with self.assertRaisesRegex(Failure, 'manifest_upload_submission_unknown'):
                runner.import_manifests(repo, proof, saved)
        self.assertEqual(self.uploads, 0)

    def test_known_uploaded_fid_is_attached_without_reupload(self):
        runner, repo, proof, saved, bodies = self.fixture(1)
        self.files['old'] = ('matrixone-daily-20261029-manifest-0.txt', bodies['dir/0.mod'])
        saved['manifest_upload_pending'] = dict(name='matrixone-daily-20261029-manifest-0.txt', path='dir/0.mod', sha256=sha256(bodies['dir/0.mod']), file_id='old')
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            runner.import_manifests(repo, proof, saved)
        self.assertEqual((self.uploads,self.attaches),(0,1))

    def test_lost_attach_without_inventory_proof_is_not_replayed(self):
        runner, repo, proof, saved, bodies = self.fixture(1)
        self.files['old'] = ('matrixone-daily-20261029-manifest-0.txt', bodies['dir/0.mod'])
        saved['manifest_upload_pending'] = dict(name='matrixone-daily-20261029-manifest-0.txt', path='dir/0.mod', sha256=sha256(bodies['dir/0.mod']), file_id='old', attach_attempted=True)
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            with self.assertRaisesRegex(Failure, 'manifest_attach_submission_unknown'):
                runner.import_manifests(repo, proof, saved)
        self.assertEqual((self.uploads,self.attaches),(0,0))

    def test_existing_same_name_different_bytes_block(self):
        runner, repo, proof, saved, bodies = self.fixture(1)
        self.files['wrong'] = ('matrixone-daily-20261029-manifest-0.txt', b'wrong')
        self.mounted['matrixone-daily-20261029-manifest-0.txt'] = 'wrong'
        with patch('cloud_daily.extract_manifests', return_value=bodies):
            with self.assertRaisesRegex(Failure, 'manifest_import_readback_mismatch'):
                runner.import_manifests(repo, proof, saved)
        self.assertEqual(self.uploads,0)

    def test_completed_import_reverifies_without_archive_read_or_mutation(self):
        runner, repo, proof, saved, bodies = self.fixture(1)
        self.files['old'] = ('x', bodies['dir/0.mod'])
        saved.update(manifests=[dict(file_evidence('old', bodies['dir/0.mod']), path='dir/0.mod')], manifest_import_complete=True)
        with patch('cloud_daily.extract_manifests', side_effect=AssertionError('no ZIP read')):
            runner.import_manifests(repo, proof, saved)
        self.assertEqual((self.uploads,self.attaches),(0,0))

if __name__ == '__main__':
    unittest.main()
