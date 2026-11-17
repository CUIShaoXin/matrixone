import unittest

from review_model import is_kimi_model, resolve_review_model
from source_code_review import parse as parse_code
from api_port_review import parse_review


class API:
    def __init__(self, models):
        self.models = models

    def request(self, path):
        assert path == '/aistudio/model-policy'
        return {'payload': {'data': {'default_model': 'deepseek-v4.1-flash', 'models': self.models}}}

    @staticmethod
    def data(value):
        return value['payload']['data']


class ReviewModelTests(unittest.TestCase):
    def test_current_kimi_alias_is_selected_and_legacy_alias_still_works(self):
        self.assertEqual(resolve_review_model(API(['deepseek-v4.1-flash', 'kimi-k3.1-pro'])), 'kimi-k3.1-pro')
        self.assertEqual(resolve_review_model(API(['kimi-k3'])), 'kimi-k3')
        with self.assertRaisesRegex(ValueError, 'kimi_model_unavailable'):
            resolve_review_model(API(['deepseek-v4.1-flash']))

    def test_both_parsers_accept_current_kimi_alias(self):
        commit = '1' * 40
        call = dict(type='matrixflow.explore.llm_call', call_id='one', model='kimi-k3.1-pro', status='completed')
        task = dict(status=dict(state='completed', message=dict(parts=[dict(kind='data', data=call)])))
        code = dict(schema='matrix_code_review_findings_v1', repository='matrixone', commit=commit, findings=[])
        api = dict(schema='matrix_api_port_source_review_v1', repository='matrixone', commit=commit, findings=[])
        task['status']['message']['parts'].append(dict(kind='text', text=__import__('json').dumps(code)))
        self.assertTrue(is_kimi_model('kimi-k3.1-pro'))
        self.assertTrue(is_kimi_model('kimi-k3'))
        self.assertFalse(is_kimi_model('deepseek-v4.1-flash'))
        self.assertEqual(parse_code(task, 'matrixone', commit, 'primary')[0], code)
        task['status']['message']['parts'][-1]['text'] = __import__('json').dumps(api)
        self.assertEqual(parse_review(task, 'matrixone', commit)[0], api)


if __name__ == '__main__':
    unittest.main()
