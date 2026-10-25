import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import knowledge_gate as kb
from source_code_review import accepted,context_for,review_repository
from test_pipeline_recovery import Job

class UnifiedTests(unittest.TestCase):
 def test_cached_code_rejects_another_archive_even_with_matching_hash(self):
  import types
  from api_port_review import sha
  raw=json.dumps(dict(repository='repo',commit='a'*40,archive_proof=dict(report_date='2026-10-25',sha256='old'))).encode()
  job=Job(None);job.state['code_repositories']={'repo':dict(accepted=True,result=dict(key='result',sha256=sha(raw),bytes=len(raw)))}
  job.objects=types.SimpleNamespace(call=lambda *a:(200,{},raw))
  with self.assertRaisesRegex(ValueError,'identity_mismatch'):review_repository(job,'repo',dict(commit='a'*40,report_date='2026-10-25',sha256='current'))
 def test_resumed_publication_revalidates_object_hash(self):
  import types
  from daily_pipeline import verify_publication
  receipt=dict(report_date='2026-10-25',commits={'repo':'a'*40},kb_marker_retrieved=True,sent=False,expires_at_utc='2099-01-01T00:00:00+00:00',published=dict(key='report',bytes=3,sha256='bad'),url='https://example.test',component_details=[])
  api=types.SimpleNamespace(file=lambda fid:json.dumps(receipt).encode());objects=types.SimpleNamespace(call=lambda *a,**k:(200,{},b'new'))
  with self.assertRaisesRegex(Exception,'hash_mismatch'):verify_publication(api,objects,'id','2026-10-25',receipt['commits'])
 def test_invalid_or_unretained_code_evidence_is_not_reported(self):
  finding=dict(id='CR-1',severity='high',status='needs_validation',title='x',trigger='x',impact='x',reasoning='x',suggested_fix='x',verification='x',evidence=[dict(path='x.go',line=2,quote='missing')])
  value={'decisions':[{'id':'CR-1','verdict':'retain'}],'findings':[finding]}
  keep,reject=accepted(value,{'x.go':{2:'real source'}});self.assertEqual(keep,[]);self.assertEqual(len(reject),1)
  finding['evidence'][0]['quote']='real';keep,_=accepted(value,{'x.go':{2:'real source'}});self.assertEqual(len(keep),1)
  value['decisions'][0]['verdict']='needs_context';self.assertEqual(accepted(value,{'x.go':{2:'real source'}})[0],[])
 def test_code_context_redacts_literals_and_reports_missing_requests(self):
  path='moi/pkg/service/workspace/invitation_accept.go'
  files={path:dict(lines=['package workspace','var api_key = "private-literal"','func Accept() {}'],sha256='x',bytes=50)}
  context,meta,evidence=context_for('matrixflow',{'commit':'a'*40,'report_date':'2026-10-25'},files,[dict(path='missing.go')])
  self.assertNotIn('private-literal',context);self.assertNotIn(2,evidence[path]);self.assertEqual(meta['missing_requested_files'],['missing.go'])
 def test_knowledge_identity_does_not_use_filename(self):
  self.assertEqual(kb.matching([dict(source_file_id='other',file_name='same.md')],'wanted'),[])
 def test_uncertain_append_is_not_repeated(self):
  class API:
   def __init__(self):self.appends=0
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    if path.endswith('/sources'):self.appends+=1;raise TimeoutError()
    return {}
  api=API();job=Job(api)
  # Feed a deterministic increasing monotonic clock to reach the explicit unknown-state gate.
  with patch.object(kb,'rows',return_value=[]),patch.object(kb.time,'sleep'),patch.object(kb.time,'monotonic',side_effect=range(0,2000,20)):
   with self.assertRaises(ValueError):kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],deadline_seconds=1000,poll_seconds=0)
  self.assertEqual(api.appends,1)
 def test_failed_existing_source_never_reappended(self):
  job=Job(None)
  with patch.object(kb,'rows',return_value=[dict(source_file_id='fid',ingest_status='failed')]):
   with self.assertRaisesRegex(ValueError,'requires_backend_repair'):kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
 def test_workflow_has_no_send_schedule_push_or_historical_fallback(self):
  workflow=(Path(__file__).parents[2]/'workflows/moi-daily-cloud-acceptance.yml')
  if workflow.exists():
   text=workflow.read_text();self.assertNotIn('schedule:',text);self.assertNotIn('push:',text);self.assertNotIn('39885692751',text)

if __name__=='__main__':unittest.main()
