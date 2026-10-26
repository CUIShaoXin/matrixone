import io
import tempfile
import unittest
import zipfile
from pathlib import Path
import api_port_review as m

class SourceReviewTests(unittest.TestCase):
    def test_large_router_does_not_starve_cited_handler_or_listener_in_focused_review(self):
        server='moi/pkg/api/server.go';handler='moi/pkg/api/handlers/sandbox_terminal.go';listener='workers/go-worker/pkg/worker/health.go'
        lines=['// '+('large route unrelated text '*9) for _ in range(2600)]
        lines[450]='productGroup.HandleFunc("GET /terminal/ws", sandboxHandler.ServeTerminalWS)'
        files={server:dict(lines=lines,sha256='router',bytes=800000),handler:dict(lines=['package handlers','func (s *Sandbox) ServeTerminalWS() {','  validateTerminalToken()','}'],sha256='handler',bytes=100),listener:dict(lines=['package worker','func NewPprofServer(addr string) {}'],sha256='listener',bytes=60)}
        prior={'findings':[{'evidence':[{'path':server,'line':451}]}]}
        context,meta,evidence=m.context_for('matrixflow',{'commit':'a'*40,'report_date':'2026-10-26'},files,[],[{'path':handler},{'path':listener}],prior,focused=True)
        self.assertIn(handler,evidence);self.assertIn(listener,evidence);self.assertIn(451,evidence[server])
        self.assertIn('validateTerminalToken()',context);self.assertLess(meta['context_bytes'],91000)
        self.assertEqual(meta['context_policy'],'balanced_final_focus_v1')

    def test_split_fence_and_repeated_complete_result_are_not_duplicate_json(self):
        import json
        value={'schema':m.SCHEMA,'repository':'taas','commit':'a'*40,'findings':[]}
        raw=json.dumps(value)
        task={'status':{'message':{'parts':[{'kind':'text','text':'```json\n'+raw},{'kind':'text','text':'```'},{'kind':'text','text':'```json\n'+raw+'\n```'}]}}}
        self.assertEqual(m.task_json(task),value)

    def test_transport_fragments_are_joined_without_changing_string_content(self):
        task={'status':{'message':{'parts':[{'kind':'text','text':'{"value":"frag'},{'kind':'text','text':'mented"}'}]}}}
        self.assertEqual(m.task_json(task),{'value':'fragmented'})

    def test_conflicting_complete_results_cannot_be_silently_selected(self):
        task={'status':{'message':{'parts':[{'kind':'text','text':'{"findings":[]}'}]}},'artifacts':[{'parts':[{'kind':'text','text':'{"findings":[1]}'}]}]}
        with self.assertRaisesRegex(ValueError,'model_result_ambiguous'):m.task_json(task)

    def test_extra_prose_or_incomplete_duplicate_is_not_repaired(self):
        import json
        for text in ('{"findings":[]} unfinished','{"findings":[]}{"findings":['):
            with self.assertRaises(json.JSONDecodeError):m.task_json({'status':{'message':{'parts':[{'kind':'text','text':text}]}}})

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
