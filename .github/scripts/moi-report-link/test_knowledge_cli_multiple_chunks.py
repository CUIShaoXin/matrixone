import contextlib,copy,io,json,subprocess,types,unittest
from pathlib import Path
from unittest.mock import patch
from knowledge_cli_gate import command_v2,verify,SCHEMA_V2,audit_v2_legacy as audit
from test_knowledge_cli_gate import TARGETS,task
from knowledge_cli_gate import command

class MultipleChunkTests(unittest.TestCase):
 def execute(self,mutate=None):
  cited=[]
  def invoke(args,**kwargs):
   if args[2]=='search':
    request=json.loads(Path(args[args.index('--json-file')+1]).read_text())
    target=next(t for t in TARGETS if t['file_id']==request['file_ids'][0])
    def chunk(fid,marker,cid):return dict(file_id=fid,semantic_model_id=80001,chunk_id=cid,content_preview=marker,content_preview_chars=len(marker),content_chars=len(marker),content_preview_truncated=False)
    chunks=[chunk('unrelated',target['marker'],'z'),chunk(target['file_id'],'neighbor','b'),chunk(target['file_id'],target['marker'],'a')]
    if mutate:mutate(chunks)
    Path(args[args.index('--output')+1]).write_text(json.dumps(dict(artifact_id='rag-'+target['file_id'],chunks=chunks)))
    return types.SimpleNamespace(stdout='{}')
   self.assertEqual(args[2],'cite');cited.extend(args[3:])
   return types.SimpleNamespace(stdout=json.dumps(dict(call_id='cite2',output=dict(accepted=True,source_count=2))))
  code=command_v2(TARGETS).split('\n',1)[1].rsplit('MATRIX_KB_READ_ONLY',1)[0]
  output=io.StringIO()
  with patch('subprocess.run',side_effect=invoke),contextlib.redirect_stdout(output):exec(code,{})
  return json.loads(output.getvalue()),cited
 def test_actual_selected_indices_and_exact_files(self):
  proof,cited=self.execute()
  self.assertEqual([cited[i+1] for i,v in enumerate(cited) if v=='--indices'],['2','2'])
  self.assertEqual([s['f'] for s in proof['searches']],['f1','f2'])
  self.assertEqual(proof['schema'],SCHEMA_V2)
 def test_wrong_file_marker_does_not_qualify(self):
  with self.assertRaisesRegex(AssertionError,'no_complete'):self.execute(lambda c:c[2].update(file_id='wrong'))
 def test_truncated_matching_chunk_does_not_qualify(self):
  with self.assertRaisesRegex(AssertionError,'no_complete'):self.execute(lambda c:c[2].update(content_preview_truncated=True))
 def test_false_full_length_does_not_qualify(self):
  with self.assertRaisesRegex(AssertionError,'no_complete'):self.execute(lambda c:c[2].update(content_chars=999))
 def test_v2_native_proof_is_bound_to_new_command(self):
  value=task();value['history'][0]['arguments']['command']=command_v2(TARGETS)
  proof=json.loads(value['history'][1]['output']['output']['stdout']);proof['schema']=SCHEMA_V2
  value['history'][1]['output']['output']['stdout']=json.dumps(proof)
  self.assertEqual(len(verify(value,TARGETS)),2)
 def test_schema_substitution_cannot_rewrite_old_contract(self):
  value=task();proof=json.loads(value['history'][1]['output']['output']['stdout']);proof['schema']=SCHEMA_V2
  value['history'][1]['output']['output']['stdout']=json.dumps(proof)
  with self.assertRaises(ValueError):verify(value,TARGETS)
 def test_failed_v1_keeps_request_and_original_clock(self):
  original=dict(started_epoch=100,attempts=[dict(task_id='old',request_id='immutable')],status='completed')
  legacy=copy.deepcopy(original)
  value=task();result=value['history'][1]['output']['output']
  result.update(exit_code=1,stderr='Traceback line 18\nAssertionError\n',knowledge_investigation=dict(last_search=dict(returned_chunks=3)))
  job=types.SimpleNamespace(state=dict(commits={'repo':'sha'},model_tasks={'repo_kb_files_scope_cli_v1':legacy}),
      api=types.SimpleNamespace(rpc=lambda *args:value),journal=types.SimpleNamespace(save=lambda:None))
  with patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]),patch('kimi_recovery.run_review',return_value='new-proof') as run:
   self.assertEqual(audit(job,TARGETS,'files'),'new-proof')
  self.assertEqual(legacy,original)
  new=job.state['model_tasks']['repo_kb_files_scope_cli_v2']
  self.assertEqual(new['started_epoch'],100);self.assertTrue(new['original_deadline_preserved'])
  self.assertEqual(run.call_args.kwargs['max_attempts'],2)
 def test_unrelated_failed_v1_contract_is_not_replaced(self):
  value=task();value['history'][1]['output']['output']['exit_code']=1
  job=types.SimpleNamespace(state=dict(commits={'repo':'sha'},model_tasks={'repo_kb_files_scope_cli_v1':dict(started_epoch=100,attempts=[dict(task_id='old')])}),api=types.SimpleNamespace(rpc=lambda *args:value))
  with self.assertRaisesRegex(ValueError,'not_multi_chunk'):audit(job,TARGETS,'files')

if __name__=='__main__':unittest.main()
