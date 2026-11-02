"""Actual truncated search shape must cause a verified full evidence read."""
import contextlib,copy,hashlib,io,json,subprocess,types,unittest
from pathlib import Path
from unittest.mock import patch
from knowledge_cli_fulltext import command,SCHEMA,audit
from knowledge_cli_gate import verify
from test_knowledge_cli_gate import TARGETS,task

class FullTextTests(unittest.TestCase):
 def execute(self,mutate_read=None,mutate_search=None,read_error=False):
  reads=[];cited=[]
  def invoke(args,**kwargs):
   if args[2]=='search':
    request=json.loads(Path(args[args.index('--json-file')+1]).read_text());t=next(t for t in TARGETS if t['file_id']==request['file_ids'][0])
    def chunk(fid,marker,cid):return dict(file_id=fid,semantic_model_id=80001,chunk_id=cid,content_preview=(marker+' '+('x'*160))[:120],content_preview_chars=120,content_chars=420,content_preview_truncated=True)
    chunks=[chunk('unrelated',t['marker'],'z'),chunk(t['file_id'],'neighbor','b'),chunk(t['file_id'],t['marker'],'a')]
    if mutate_search:mutate_search(chunks)
    Path(args[args.index('--output')+1]).write_text(json.dumps(dict(artifact_id='rag-'+t['file_id'],chunks=chunks)))
    return types.SimpleNamespace(stdout='{}')
   if args[2]=='read-evidence':
    r=json.loads(args[args.index('--json')+1]);reads.append(r)
    self.assertEqual(r['limit_chars'],8000);self.assertNotIn('cursor',r)
    if read_error:raise subprocess.CalledProcessError(1,args)
    t=next(t for t in TARGETS if t['file_id']==r['file_id'])
    full={k:r[k] for k in ('artifact_id','file_id','chunk_id','semantic_model_id')}
    full.update(has_more=False,content=t['marker']+' full original passage '+('x'*6000));full['content_chars']=len(full['content'])
    if mutate_read:mutate_read(full)
    return types.SimpleNamespace(stdout=json.dumps(dict(output=full)))
   self.assertEqual(args[2],'cite');cited.extend(args[3:]);return types.SimpleNamespace(stdout=json.dumps(dict(call_id='cite-full',output=dict(accepted=True,source_count=2))))
  code=command(TARGETS).split('\n',1)[1].rsplit('MATRIX_KB_FULL_READ_ONLY',1)[0];out=io.StringIO()
  with patch('subprocess.run',side_effect=invoke),contextlib.redirect_stdout(out):exec(code,{})
  return json.loads(out.getvalue()),reads,cited
 def test_truncated_preview_reads_exact_full_chunk_and_cites_actual_indices(self):
  proof,reads,cited=self.execute();self.assertEqual(len(reads),2)
  self.assertEqual([cited[i+1] for i,v in enumerate(cited) if v=='--indices'],['2','2'])
  self.assertEqual(proof['schema'],SCHEMA)
  self.assertLess(len(json.dumps(proof)),2500)
  self.assertTrue(all(p['read_protocol']=='search_then_full_read_evidence' for p in proof['searches']))
 def test_wrong_file_read_rejected(self):
  with self.assertRaisesRegex(AssertionError,'identity'):self.execute(lambda p:p.update(file_id='wrong'))
 def test_wrong_kb_read_rejected(self):
  with self.assertRaisesRegex(AssertionError,'identity'):self.execute(lambda p:p.update(semantic_model_id=1))
 def test_wrong_chunk_read_rejected(self):
  with self.assertRaisesRegex(AssertionError,'identity'):self.execute(lambda p:p.update(chunk_id='wrong'))
 def test_wrong_artifact_read_rejected(self):
  with self.assertRaisesRegex(AssertionError,'identity'):self.execute(lambda p:p.update(artifact_id='wrong'))
 def test_partial_full_read_rejected(self):
  with self.assertRaisesRegex(AssertionError,'incomplete'):self.execute(lambda p:p.update(has_more=True))
 def test_missing_marker_rejected(self):
  with self.assertRaisesRegex(AssertionError,'marker'):self.execute(lambda p:p.update(content='missing',content_chars=7))
 def test_false_full_read_length_rejected(self):
  with self.assertRaisesRegex(AssertionError,'length'):self.execute(lambda p:p.update(content_chars=0))
 def test_missing_full_read_content_rejected(self):
  with self.assertRaisesRegex(AssertionError,'content_missing'):self.execute(lambda p:p.update(content=None))
 def test_tool_error_rejected(self):
  with self.assertRaises(subprocess.CalledProcessError):self.execute(read_error=True)
 def test_wrong_file_preview_not_read(self):
  with self.assertRaisesRegex(AssertionError,'marker'):self.execute(lambda p:p.update(content='missing',content_chars=7),lambda c:c[2].update(file_id='wrong'))
 def full_task(self):
  value=task();value['history'][0]['arguments']['command']=command(TARGETS)
  proof=json.loads(value['history'][1]['output']['output']['stdout']);proof['schema']=SCHEMA
  for p in proof['searches']:p.update(read_protocol='search_then_full_read_evidence',content_chars=len(p['p']),content_sha256=hashlib.sha256(p['p'].encode()).hexdigest())
  value['history'][1]['output']['output']['stdout']=json.dumps(proof);return value
 def test_native_final_source_proof_accepted(self):self.assertEqual(len(verify(self.full_task(),TARGETS)),2)
 def test_empty_or_wrong_last_native_sources_rejected(self):
  value=self.full_task();value['artifacts'].append(dict(metadata=dict(tool='select_final_sources',cite_then_write=True,source_refs=[])))
  with self.assertRaises(ValueError):verify(value,TARGETS)
 def test_unknown_read_protocol_rejected(self):
  value=self.full_task();p=json.loads(value['history'][1]['output']['output']['stdout']);p['searches'][0]['read_protocol']='claimed'
  value['history'][1]['output']['output']['stdout']=json.dumps(p)
  with self.assertRaises(ValueError):verify(value,TARGETS)
 def test_failed_old_contracts_and_clocks_immutable(self):
  saved=dict(started_epoch=100,attempts=[dict(task_id='old',request_id='immutable')],status='completed');original=copy.deepcopy(saved)
  old=task();old['history'][1]['output']['output']['exit_code']=1
  job=types.SimpleNamespace(state=dict(commits={'repo':'sha'},model_tasks={'repo_kb_files_scope_cli_v2':saved}),api=types.SimpleNamespace(rpc=lambda *args:old),journal=types.SimpleNamespace(save=lambda:None))
  with patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]),patch('kimi_recovery.run_review',return_value='full-proof') as run,patch('knowledge_cli_fulltext.time.time',return_value=1000):
   self.assertEqual(audit(job,TARGETS,'files'),'full-proof')
  self.assertEqual(saved,original);new=job.state['model_tasks']['repo_kb_files_scope_cli_full_v1'];self.assertEqual(new['started_epoch'],1000)
  self.assertTrue(new['separate_repair_validation']);self.assertEqual(run.call_args.kwargs['max_attempts'],1);self.assertEqual(run.call_args.kwargs['deadline_seconds'],600)
 def test_active_old_task_blocks_new_audit(self):
  job=types.SimpleNamespace(state=dict(commits={'repo':'sha'},model_tasks={'repo_kb_files_scope_cli_v2':dict(started_epoch=100,attempts=[dict(task_id='old')])}),api=types.SimpleNamespace(rpc=lambda *args:dict(status=dict(state='working'))))
  with self.assertRaisesRegex(ValueError,'still_active'):audit(job,TARGETS,'files')
if __name__=='__main__':unittest.main()
