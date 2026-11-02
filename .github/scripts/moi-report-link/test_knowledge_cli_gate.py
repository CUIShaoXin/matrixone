import copy,json,unittest
from unittest.mock import patch
from knowledge_cli_gate import command,verify,SCHEMA
from cloud_daily import verify_rag

TARGETS=[dict(file_id='f1',marker='MARKER1'),dict(file_id='f2',marker='MARKER2')]
def task():
 searches=[dict(f=t['file_id'],a='rag_'+str(i),c='chunk'+str(i),p=t['marker'],n=len(t['marker'])) for i,t in enumerate(TARGETS)]
 proof=dict(schema=SCHEMA,searches=searches,selection=dict(accepted=True,count=2,call_id='native-cite-1'))
 call=dict(type='moi.tool.call',callId='bash1',toolId='mcp__moi-tools__bash',arguments={'command':command(TARGETS)})
 result=dict(type='moi.tool.result',callId='bash1',toolId=call['toolId'],output=dict(call_id='bash1',tool_id='bash',output=dict(exit_code=0,output_truncated=False,stderr='',stdout=json.dumps(proof))))
 refs=[dict(file_id=s['f'],artifact_id=s['a'],chunk_ids=[s['c']],semantic_model_id=80001) for s in searches]
 return dict(status=dict(state='completed'),history=[call,result],artifacts=[dict(metadata=dict(tool='select_final_sources',cite_then_write=True,source_refs=refs))])
class NativeCLITests(unittest.TestCase):
 def reject(self,mutate):
  value=task();mutate(value)
  with self.assertRaisesRegex(ValueError,'rag_'):verify(value,TARGETS)
 def mutate_proof(self,fn):
  def change(t):
   result=t['history'][1]['output']['output'];p=json.loads(result['stdout']);fn(p);result['stdout']=json.dumps(p)
  self.reject(change)
 def test_exact_native_command_and_final_source_refs_pass(self):
  self.assertEqual(len(verify(task(),TARGETS)),2);self.assertEqual(len(verify_rag(task(),TARGETS)),2)
 def test_tool_timeout_option_preserves_exact_command(self):
  t=task();t['history'][0]['arguments']['timeout']=300
  self.assertEqual(len(verify(t,TARGETS)),2)
 def test_other_shell_options_are_rejected(self):self.reject(lambda t:t['history'][0]['arguments'].update(extra='unexpected'))
 def test_arbitrary_model_shell_cannot_supply_proof(self):self.reject(lambda t:t['history'][0]['arguments'].update(command='echo fake'))
 def test_changed_target_cannot_supply_proof(self):
  t=task();targets=copy.deepcopy(TARGETS);targets[0]['file_id']='another'
  with self.assertRaises(ValueError):verify(t,targets)
 def test_incomplete_task(self):self.reject(lambda t:t['status'].update(state='running'))
 def test_tool_summary_never_qualifies(self):self.reject(lambda t:t['history'][1].update(output={'type':'astra.external_tool_result_summary.v1','preview':'accepted=true'}))
 def test_truncated_stdout(self):self.reject(lambda t:t['history'][1]['output']['output'].update(output_truncated=True))
 def test_tool_failure(self):self.reject(lambda t:t['history'][1]['output']['output'].update(exit_code=1))
 def test_mismatched_call_id(self):self.reject(lambda t:t['history'][1]['output'].update(call_id='other'))
 def test_native_selection_missing(self):self.reject(lambda t:t.update(artifacts=[]))
 def test_wrong_native_selection_file(self):self.reject(lambda t:t['artifacts'][0]['metadata']['source_refs'][0].update(file_id='wrong'))
 def test_wrong_native_selection_chunk(self):self.reject(lambda t:t['artifacts'][0]['metadata']['source_refs'][0].update(chunk_ids=['wrong']))
 def test_wrong_native_selection_artifact(self):self.reject(lambda t:t['artifacts'][0]['metadata']['source_refs'][0].update(artifact_id='wrong'))
 def test_unaccepted_citation(self):self.mutate_proof(lambda p:p['selection'].update(accepted=False))
 def test_marker_missing(self):self.mutate_proof(lambda p:p['searches'][0].update(p='wrong',n=5))
 def test_missing_or_duplicate_search(self):self.mutate_proof(lambda p:p.update(searches=[p['searches'][0],p['searches'][0]]))
 def test_false_full_preview_length(self):self.mutate_proof(lambda p:p['searches'][0].update(n=999))
if __name__=='__main__':unittest.main()
