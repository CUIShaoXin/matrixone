"""Stage failures retain machine reasons without leaking arbitrary exception text."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from pipeline_telemetry import span


class StageFailureEvidenceTests(unittest.TestCase):
    def observe(self, error):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'events.jsonl'
            with patch.dict(os.environ, {'MATRIX_TIMINGS_FILE': str(path)}), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(type(error)) as caught:
                    with span('component_knowledge', repository='taas'):
                        raise error
            self.assertIs(caught.exception, error)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(rows[0]['kind'], 'stage_start')
            self.assertEqual(rows[-1]['kind'], 'stage_end')
            self.assertEqual(rows[-1]['status'], 'failed')
            return rows[-1]

    def test_kb_deadline_retains_precise_machine_reason_in_stage_event(self):
        row = self.observe(ValueError('model_phase_deadline_exceeded'))
        self.assertEqual(row['repository'], 'taas')
        self.assertEqual(row['safe_code'], 'model_phase_deadline_exceeded')
        self.assertEqual(row['error_type'], 'ValueError')

    def test_private_error_body_is_not_retained(self):
        row = self.observe(ValueError('PRIVATE_ERROR https://example.test/?token=PRIVATE_TOKEN'))
        self.assertNotIn('safe_code', row)
        self.assertNotIn('PRIVATE_', json.dumps(row))

    def test_http_failure_retains_status_without_request_url(self):
        row = self.observe(urllib.error.HTTPError('https://example.test/PRIVATE_TOKEN',
                                                401, 'PRIVATE_ERROR', {}, None))
        self.assertEqual(row['http_status'], 401)
        self.assertNotIn('PRIVATE_', json.dumps(row))


if __name__ == '__main__':
    unittest.main()
