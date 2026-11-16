import json
import unittest
from unittest.mock import patch

from native_upload import json_bytes, upload_named_once


class Objects:
    def __init__(self):
        self.values = {}

    def call(self, method, key, raw=None, headers=None, **kwargs):
        if method == 'PUT' and (headers or {}).get('if-none-match') == '*' and key in self.values:
            raise RuntimeError('minio_http_412')
        if method == 'GET' and key not in self.values:
            raise RuntimeError('minio_http_404')
        if method == 'PUT':
            self.values[key] = raw
        return 200, {}, self.values.get(key, b'')

    def publish(self, key, raw, content_type):
        self.values[key] = raw


class API:
    def __init__(self, raw, fail_upload=False):
        self.raw = raw
        self.fail_upload = fail_upload
        self.uploads = 0
        self.files = {}
        self.name = 'matrix-daily-test.json'

    def data(self, value):
        return value['payload']['data']

    def request(self, path, payload, timeout=90):
        rows = [dict(id=fid, name=self.name, volume_id=130001)
                for fid, body in self.files.items() if body == self.raw]
        return {'payload': {'data': {'total': len(rows), 'list': rows}}}

    def file(self, fid):
        return self.files[fid]

    def upload(self, name, raw):
        self.uploads += 1
        fid = '11111111-1111-4111-8111-111111111111'
        self.files[fid] = raw
        if self.fail_upload:
            raise TimeoutError()
        return dict(file_id=fid)


class NativeUploadTests(unittest.TestCase):
    def setUp(self):
        patcher = patch('native_upload.SignedObjects.call',
                        lambda objects, *args, **kwargs: objects.call(*args, **kwargs))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_uncertain_upload_is_recovered_without_a_second_submission(self):
        raw = json_bytes({'complete': True})
        api = API(raw, fail_upload=True)
        objects = Objects()
        first = upload_named_once(api, objects, 'batch/upload-intent.json', api.name, raw)
        second = upload_named_once(api, objects, 'batch/upload-intent.json', api.name, raw)
        self.assertEqual(first, second)
        self.assertEqual(api.uploads, 1)

    def test_attempted_missing_upload_blocks_instead_of_replaying(self):
        raw = b'{}'
        api = API(raw)
        objects = Objects()
        objects.publish('batch/upload-intent.json', json_bytes({
            'schema': 'matrix_named_upload_intent_v1', 'name': api.name,
            'bytes': len(raw), 'sha256': __import__('native_upload').sha(raw),
            'volume_id': 130001, 'submission_attempted': True}), 'application/json')
        with self.assertRaisesRegex(ValueError, 'native_upload_submission_unknown'):
            upload_named_once(api, objects, 'batch/upload-intent.json', api.name, raw)
        self.assertEqual(api.uploads, 0)


if __name__ == '__main__':
    unittest.main()
