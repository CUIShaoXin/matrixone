import io
import tempfile
import unittest
import zipfile
from pathlib import Path
import api_port_review as m

class SourceReviewTests(unittest.TestCase):
    def test_actual_event_types_and_unclosed_presentation_fence(self):
        import json
        result={'schema':m.SCHEMA,'repository':'taas','commit':'a'*40,'findings':[]}
        events=[{'type':['object','null']}, {'type':'matrixflow.explore.llm_call','call_id':'one','model':'kimi-k3','status':'completed'}, {'type':'matrixflow.explore.llm_call','call_id':'one','model':'kimi-k3','status':'started'}]
        task={'status':{'state':'completed','message':{'parts':[{'kind':'text','text':'```json\n'+json.dumps(result)}]}},'metadata':events}
        parsed,calls=m.parse_review(task,'taas','a'*40)
        self.assertEqual(parsed,result)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]['status'],'completed')
        task['status']['message']['parts'][0]['text']='```json\n'+json.dumps(result)[:-1]
        with self.assertRaises(json.JSONDecodeError):m.parse_review(task,'taas','a'*40)

    def test_routes_listener_and_auth_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            raw=b'package main\nfunc main() {\n router.GET("/admin", handler)\n http.ListenAndServe(":8080", router)\n AuthMiddleware()\n}\n'
            (root/'server.go').write_bytes(raw)
            files={'server.go':dict(lines=raw.decode().splitlines(),sha256=m.sha(raw),bytes=len(raw))}
            hits,counts=m.inventory(root,files)
            self.assertEqual(counts,{'api':1,'listener':1,'auth':1})
            context,meta,evidence=m.context_for('matrixone',{'commit':'a'*40,'report_date':'2026-10-23'},files,hits)
            self.assertEqual(evidence['server.go'][3],' router.GET("/admin", handler)')
            self.assertIn('00003|',context)

    def test_scope_and_specs(self):
        self.assertTrue(m.eligible('docs/api/openapi.yaml'))
        self.assertFalse(m.eligible('vendor/server.go'))
        self.assertFalse(m.eligible('pkg/x_test.go'))
        self.assertFalse(m.eligible('docs/guide.go'))

    def test_reject_invisible_or_ambiguous_evidence(self):
        f=dict(id='AP-01',category='api',severity='medium',status='needs_validation',title='risk',trigger='condition',impact='impact',reasoning='chain',suggested_fix='fix',verification='test',evidence=[dict(path='a.go',line=99,quote='auth()')])
        r={'findings':[f],'decisions':[{'id':'AP-01','verdict':'retain'}]}
        ok,bad,repairs=m.accept(r,{'a.go':{1:'auth()',2:'auth()'}})
        self.assertFalse(ok)
        ok,bad,repairs=m.accept(r,{'a.go':{1:'auth()'}})
        self.assertEqual(ok[0]['evidence'][0]['line'],1)
        r['decisions'][0]['verdict']='needs_context'
        self.assertFalse(m.accept(r,{'a.go':{1:'auth()'}})[0])

    def test_archive_path_escape_rejected_before_write(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            z.comment=b'a'*40
            z.writestr('root/../escape.go','package main')
            z.writestr('root/go.mod','module x')
        raw=stream.getvalue()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'unsafe_zip_path'):
                m.extract(raw,{'bytes':len(raw),'sha256':m.sha(raw),'commit':'a'*40},Path(tmp))

if __name__=='__main__':unittest.main()
