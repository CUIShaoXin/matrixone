import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import knowledge_gate as kb
from source_code_review import accepted,context_for,review_repository
from test_pipeline_recovery import Job

class UnifiedTests(unittest.TestCase):
 def focus_fixture(self):
  expected={'date':'2026-10-26','components':[dict(repo='matrixone',name='golang.org/x/crypto',advisories=[dict(id='GHSA-test',details='SSH servers which use the affected certificate callback may panic.')])]}
  item=dict(repo='matrixone',name='golang.org/x/crypto',risk='在使用受影响证书回调时可能触发服务崩溃。',action='核对SSH证书回调的配置与实际调用路径。',evidence=[dict(id='GHSA-test',quote='affected certificate callback')])
  value=dict(schema='matrix_component_focus_v1',date=expected['date'],components=[item])
  return expected,value
 def test_focus_accepts_only_structured_final_with_exact_advisory_quote(self):
  from combined_renderer import parse_focus
  expected,value=self.focus_fixture();calls=[dict(model='kimi-k3',status='completed')]
  with patch('api_port_review.task_json',return_value=value),patch('api_port_review.llm_calls',return_value=calls):
   self.assertEqual(parse_focus(dict(status={'state':'completed'}),expected),(value,calls))
 def test_focus_rejects_unmatched_quote_and_extra_components(self):
  from combined_renderer import parse_focus
  expected,value=self.focus_fixture()
  with patch('api_port_review.task_json',return_value=value),patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]):
   value['components'][0]['evidence'][0]['quote']='invented advisory quote'
   with self.assertRaisesRegex(ValueError,'quote_mismatch'):parse_focus(dict(status={'state':'completed'}),expected)
   value['components'].append(copy.deepcopy(value['components'][0]))
   with self.assertRaisesRegex(ValueError,'coverage_mismatch'):parse_focus(dict(status={'state':'completed'}),expected)
 def test_focus_shortens_only_exact_long_quote_after_full_source_match(self):
  from combined_renderer import parse_focus
  expected,value=self.focus_fixture();quote='verified advisory source '*14
  expected['components'][0]['advisories'][0]['details']=quote
  value['components'][0]['evidence'][0]['quote']=quote
  with patch('api_port_review.task_json',return_value=value),patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]):
   result,_=parse_focus(dict(status={'state':'completed'}),expected)
  ref=result['components'][0]['evidence'][0]
  self.assertEqual(ref['quote'],quote[:300]);self.assertEqual(ref['original_quote_chars'],len(quote))
 def test_focus_rejects_wrong_model_and_unexpected_tool_calls(self):
  from combined_renderer import parse_focus
  expected,value=self.focus_fixture()
  with patch('api_port_review.task_json',return_value=value),patch('api_port_review.llm_calls',return_value=[dict(model='other',status='completed')]):
   with self.assertRaisesRegex(ValueError,'actual_kimi_missing'):parse_focus(dict(status={'state':'completed'}),expected)
  with patch('api_port_review.task_json',return_value=value),patch('api_port_review.llm_calls',return_value=[dict(model='kimi-k3',status='completed')]):
   with self.assertRaisesRegex(ValueError,'unexpected_tool'):parse_focus(dict(status={'state':'completed'},events=[{'type':'moi.tool.call'}]),expected)
 def test_focus_never_parses_reasoning_markdown_and_binds_original_hashes(self):
  from combined_renderer import focus_inputs
  from api_port_review import sha
  files={};results={}
  for repo in ('matrixone','taas','matrixflow'):
   scan=dict(commit='a'*40,facts=dict(report_date_shanghai='2026-10-26',priority_components=[dict(name='package',ecosystem='Go',versions={'1.0.0':[]},vulnerability_ids=['id'])]),full_advisories={'id':dict(details='The affected API can panic when a callback is absent.')})
   files[(repo,'osv')]=json.dumps(scan).encode();files[(repo,'employee')]=b'We need to draft a report. No completed final answer.'
   results[repo]=dict(commit='a'*40,artifacts={k:dict(bytes=len(files[(repo,k)]),sha256=sha(files[(repo,k)])) for k in ('osv','employee')})
  batch=dict(date='2026-10-26',results=results)
  self.assertEqual(len(focus_inputs(batch,files)['components']),3)
  files[('taas','employee')]=b'tampered'
  with self.assertRaisesRegex(ValueError,'hash_mismatch'):focus_inputs(batch,files)
 def test_structured_focus_render_bypasses_free_form_markdown_parser(self):
  from combined_renderer import render
  scan=json.dumps(dict(package_version_results=[dict(package={'name':'package'},version='1.0.0')])).encode()
  batch=dict(date='2026-10-26',results={r:dict(commit='a'*40) for r in ('matrixone','taas','matrixflow')})
  focus=[dict(repo='matrixone',commit='a'*40,name='package',label='package',risk='触发条件',action='核对实际路径')]
  code={r:dict(commit='a'*40,retained_findings=[],selected_files=1,selected_lines=1) for r in batch['results']}
  with patch('combined_renderer.subprocess.run',side_effect=AssertionError('legacy parser must not run')):
   page,count,findings=render(batch,{('matrixone','osv'):scan},code,focus=focus)
  self.assertEqual((count,findings),(1,0));self.assertIn('核对实际路径'.encode(),page)
 def test_exact_active_volume_dispatch_projection_waits_without_reappend(self):
  class API:
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    self_test.assertIsNone(payload);return {'items':[]}
  self_test=self;job=Job(API())
  failed=dict(source_file_id='fid',ingest_status='failed',error='workflow has an active volume dispatch job: job 213472d9-decc-4bf1-b52f-6306c74360a8 status running')
  with patch.object(kb,'rows',side_effect=[[failed],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  state=job.state['knowledge_registration']['fid']
  self.assertTrue(state['succeeded']);self.assertEqual(state['active_dispatch_observations'],1)
  self.assertNotIn('append_attempted',state)
 def test_active_dispatch_grace_cannot_accept_persistent_failure(self):
  import types
  job=Job(types.SimpleNamespace(data=lambda x:x,request=lambda *a,**kw:{'items':[]}))
  failed=dict(source_file_id='fid',ingest_status='failed',error='workflow has an active volume dispatch job: job 213472d9-decc-4bf1-b52f-6306c74360a8 status running')
  with patch.object(kb,'rows',return_value=[failed]):
   with self.assertRaisesRegex(ValueError,'requires_backend_repair'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],runtime_visibility_grace_seconds=0)
  self.assertTrue(job.state['knowledge_registration']['fid']['failure_evidence_recorded'])
  self.assertNotIn('succeeded',job.state['knowledge_registration']['fid'])
 def test_kb_audit_explicitly_omits_volume_filter_and_preserves_old_phase(self):
  job=Job(None)
  repo=sorted(job.state['commits'])[0]
  job.state['model_tasks']={repo+'_kb_matrixone_scope_v2':{'original':'retained'}}
  with patch('kimi_recovery.run_review',return_value=[]) as run:
   kb.audit(job,[dict(file_id='fid',marker='marker')],'matrixone')
  args=run.call_args.args
  self.assertEqual(args[2],'kb_matrixone_scope_v2')
  self.assertIn('search_rag_chunks必须省略volume_id',args[4])
  self.assertIn('不是volume_id',args[4])
 def test_knowledge_id_used_as_volume_cannot_prove_retrieval(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events'][0]['arguments']['volume_id']='80001'
  with self.assertRaisesRegex(Exception,'rag_marker_missing'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_one_failed_repository_does_not_skip_remaining_scans_or_allow_publication(self):
  from daily_pipeline import scan_components
  import types
  calls=[];failures=[]
  def scan(repo,proof):
   calls.append(repo.name)
   if repo.name=='matrixone':raise ValueError('knowledge_ingestion_failed_requires_backend_repair')
   return {'accepted':True}
  with self.assertRaisesRegex(ValueError,'component_scan_incomplete'):
   scan_components(types.SimpleNamespace(scan=scan),{r:{} for r in ('matrixone','taas','matrixflow')},lambda r,e:failures.append((r,str(e))))
  self.assertEqual(calls,['matrixone','taas','matrixflow']);self.assertEqual(failures,[('matrixone','knowledge_ingestion_failed_requires_backend_repair')])
 def test_missing_runtime_source_view_is_reobserved_without_duplicate_registration(self):
  class API:
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    self_test.assertIsNone(payload);return {'items':[]}
  self_test=self;job=Job(API())
  failed=dict(source_file_id='fid',ingest_status='failed',error='workflow execution 11111111-1111-1111-1111-111111111111 not found: domain object not found')
  with patch.object(kb,'rows',side_effect=[[failed],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  state=job.state['knowledge_registration']['fid']
  self.assertTrue(state['succeeded']);self.assertEqual(state['missing_runtime_observations'],1);self.assertNotIn('append_attempted',state)
 def test_missing_runtime_view_has_a_bounded_grace_and_cannot_be_accepted(self):
  class API:
   @staticmethod
   def data(x):return x
   def request(self,*a,**kw):return {'items':[]}
  job=Job(API());failed=dict(source_file_id='fid',ingest_status='failed',error='workflow execution 11111111-1111-1111-1111-111111111111 not found: domain object not found')
  with patch.object(kb,'rows',return_value=[failed]):
   with self.assertRaisesRegex(ValueError,'knowledge_ingestion_failed_requires_backend_repair'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],runtime_visibility_grace_seconds=0)
  self.assertNotIn('succeeded',job.state['knowledge_registration']['fid'])
 def test_actual_terminal_source_failure_without_active_job_still_blocks(self):
  class API:
   @staticmethod
   def data(x):return x
   def request(self,*a,**kw):return {'items':[]}
  job=Job(API())
  with patch.object(kb,'rows',return_value=[dict(source_file_id='fid',ingest_status='failed',error='embedding failed')]):
   with self.assertRaisesRegex(ValueError,'knowledge_ingestion_failed_requires_backend_repair'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertNotIn('missing_runtime_first_observed_epoch',job.state['knowledge_registration']['fid'])
 def rag_artifact_task(self):
  events=[]
  def pair(cid,tool,args,output):
   events.extend([dict(type='moi.tool.call',callId=cid,toolId=tool,arguments=args),dict(type='moi.tool.result',callId=cid,toolId=tool,output=output)])
  pair('search','search_rag_chunks',{'file_ids':['fid']},{'type':'astra.external_tool_result_summary.v1','truncated':True,'preview':'not full evidence'})
  identity=dict(artifact_id='rag_chunks_search',file_id='fid',chunk_id='chunk',semantic_model_id=80001)
  pair('read','read_artifact',dict(identity,cursor=0),dict(identity,cursor=0,content='exact marker',has_more=False))
  pair('select','select_final_sources',{'sources':[identity]},dict(accepted=True,sources=[identity]))
  return dict(status={'state':'completed'},events=events)
 def test_actual_search_full_artifact_and_exact_selection_prove_marker(self):
  from cloud_daily import verify_rag
  proof=verify_rag(self.rag_artifact_task(),[dict(file_id='fid',marker='marker')])
  self.assertEqual(proof[0]['hits'][0]['read_call_id'],'read')
 def test_failed_selection_text_before_corrected_call_does_not_hide_real_proof(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task()
  failed=[dict(type='moi.tool.call',callId='bad-select',toolId='select_final_sources',arguments={'sources':[]}),dict(type='moi.tool.result',callId='bad-select',toolId='select_final_sources',output='select_final_sources: unsupported final answer source type ""')]
  task['events'][-2:-2]=failed
  self.assertEqual(verify_rag(task,[dict(file_id='fid',marker='marker')])[0]['file_id'],'fid')
 def test_failed_full_read_text_before_corrected_call_does_not_crash(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();args=task['events'][2]['arguments'].copy()
  failed=[dict(type='moi.tool.call',callId='bad-read',toolId='read_artifact',arguments=args),dict(type='moi.tool.result',callId='bad-read',toolId='read_artifact',output='Agent Binding MCP JSON-RPC error -32602')]
  task['events'][2:2]=failed
  self.assertEqual(verify_rag(task,[dict(file_id='fid',marker='marker')])[0]['hits'][0]['read_call_id'],'read')
 def test_failed_selection_text_alone_never_proves_acceptance(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events'][-1]['output']='unsupported final answer source type'
  with self.assertRaisesRegex(Exception,'rag_sources_not_selected'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_malformed_selected_sources_do_not_count_as_acceptance(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events'][-1]['output']={'accepted':True,'sources':['fid']}
  with self.assertRaisesRegex(Exception,'rag_sources_not_selected'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_unpaired_selection_result_never_proves_acceptance(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events']=[e for e in task['events'] if not (e['callId']=='select' and e['type']=='moi.tool.call')]
  with self.assertRaisesRegex(Exception,'rag_sources_not_selected'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_truncated_search_summary_does_not_prove_marker(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events']=[e for e in task['events'] if e['callId']!='read']
  with self.assertRaisesRegex(Exception,'rag_marker_missing'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_full_artifact_from_another_search_cannot_prove_marker(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task()
  for e in task['events']:
   if e['callId']=='read':e.get('arguments',e.get('output'))['artifact_id']='rag_chunks_other_search'
  with self.assertRaisesRegex(Exception,'rag_marker_missing'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_partial_artifact_read_is_not_accepted(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events'][3]['output']['has_more']=True
  with self.assertRaisesRegex(Exception,'rag_marker_missing'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_selected_different_chunk_in_same_file_is_rejected(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events'][-1]['output']['sources']=[dict(file_id='fid',chunk_id='other',artifact_id='rag_chunks_search')]
  with self.assertRaisesRegex(Exception,'rag_sources_not_selected'):verify_rag(task,[dict(file_id='fid',marker='marker')])
 def test_legacy_complete_search_result_still_supported(self):
  from cloud_daily import verify_rag
  task=self.rag_artifact_task();task['events']=[e for e in task['events'] if e['callId']!='read'];task['events'][1]['output']={'items':[dict(source_id='fid',item_id='chunk',content_preview='exact marker',content_preview_truncated=False)]}
  self.assertEqual(verify_rag(task,[dict(file_id='fid',marker='marker')])[0]['file_id'],'fid')
 def test_reconcile_conflict_reobserves_same_sources_without_reappend(self):
  from cloud_daily import Failure
  class API:
   def __init__(self):self.reconciles=0
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    if path.endswith('/reconcile'):self.reconciles+=1;raise Failure('moi_http_409')
    return {'items':[],'reconcile_required':True}
  api=API();job=Job(api)
  with patch.object(kb,'rows',side_effect=[[dict(source_file_id='fid',ingest_status='running')],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertEqual(api.reconciles,1);self.assertEqual(job.state['knowledge_conflicts'][0]['operation'],'source_jobs_reconcile')
  self.assertTrue(job.state['knowledge_registration']['fid']['succeeded']);self.assertNotIn('append_attempted',job.state['knowledge_registration']['fid'])
 def test_registration_conflict_never_repeats_uncertain_append(self):
  from cloud_daily import Failure
  class API:
   def __init__(self):self.appends=0
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    if path.endswith('/sources'):self.appends+=1;raise Failure('moi_http_409')
    return {'items':[]}
  api=API();job=Job(api)
  with patch.object(kb,'rows',side_effect=[[],[],[],[],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertEqual(api.appends,1);self.assertTrue(job.state['knowledge_registration']['fid']['succeeded'])
  self.assertEqual(job.state['knowledge_conflicts'][0]['operation'],'source_registration')
 def test_knowledge_transient_gateway_error_reobserves_same_source(self):
  from cloud_daily import Failure
  job=Job(None)
  with patch.object(kb,'rows',side_effect=[Failure('moi_http_504'),[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertTrue(job.state['knowledge_registration']['fid']['succeeded']);self.assertNotIn('append_attempted',job.state['knowledge_registration']['fid'])
 def test_moi_transient_read_recovers_but_uncertain_write_is_not_repeated(self):
  from cloud_daily import DailyAPI,Failure,publication
  api=DailyAPI('test-key')
  with patch.object(publication.ReportAPI,'request',side_effect=[Failure('moi_http_504'),{'ok':True}]) as request,patch('cloud_daily.time.sleep'):
   self.assertEqual(api.request('/semantic-models/80001/sources'),{'ok':True});self.assertEqual(request.call_count,2)
  with patch.object(publication.ReportAPI,'request',side_effect=TimeoutError()) as request:
   with self.assertRaises(TimeoutError):api.request('/workflow/v2/workflow-apps/example/executions',{'trigger_now':True})
   self.assertEqual(request.call_count,1)
 def test_moi_file_read_recovers_without_reupload(self):
  from cloud_daily import DailyAPI,publication
  with patch.object(publication.ReportAPI,'file',side_effect=[TimeoutError(),b'original']) as download,patch('cloud_daily.time.sleep'):
   self.assertEqual(DailyAPI('test-key').file('fid'),b'original');self.assertEqual(download.call_count,2)
 def test_failed_source_view_waits_for_active_job_without_reappend(self):
  class API:
   @staticmethod
   def data(x):return x
   def request(self,*a,**kw):return {'items':[dict(source_file_id='fid',job_status='running')]}
  job=Job(API())
  with patch.object(kb,'rows',side_effect=[[dict(source_file_id='fid',ingest_status='failed')],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertTrue(job.state['knowledge_registration']['fid']['succeeded']);self.assertNotIn('append_attempted',job.state['knowledge_registration']['fid'])
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
  import types
  job=Job(types.SimpleNamespace(data=lambda x:x,request=lambda *a,**k:{'items':[]}))
  with patch.object(kb,'rows',return_value=[dict(source_file_id='fid',ingest_status='failed')]):
   with self.assertRaisesRegex(ValueError,'requires_backend_repair'):kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
 def test_workflow_never_uses_push_or_fixed_historical_fallback(self):
  workflow=(Path(__file__).parents[2]/'workflows/moi-daily-cloud-acceptance.yml')
  if workflow.exists():
   text=workflow.read_text();self.assertNotIn('push:',text);self.assertNotIn('39885692751',text)
   if 'schedule:' in text:
    self.assertIn("17 20 * * *",text)
    self.assertIn('daily_delivery.py',text)
    self.assertIn('MATRIX_SCHEDULED_BATCH',text)
    self.assertIn('cancel-in-progress: false',text)

class ArchiveReverificationTests(unittest.TestCase):
 def proofs(self):
  from daily_pipeline import preflight
  return {r.name:dict(report_date='2026-10-28',repository=r.owner+'/'+r.name,
    daily_cloud_download_verified=True,minio_readback_verified=True,
    key=r.name+'.zip',bytes=3,sha256='digest',commit='a'*40) for r in preflight.REPOSITORIES}
 def test_existing_archive_mode_rechecks_every_object_without_new_acquisition(self):
  from daily_pipeline import reverify_archives
  from unittest.mock import Mock
  objects=Mock();objects.verify_object.return_value=True
  commits=reverify_archives(objects,self.proofs(),'2026-10-28')
  self.assertEqual(set(commits),{'matrixone','taas','matrixflow'});self.assertEqual(objects.verify_object.call_count,3)
  self.assertEqual(set(c.args[0] for c in objects.verify_object.call_args_list),{'matrixone.zip','taas.zip','matrixflow.zip'})
 def test_wrong_day_or_missing_archive_cannot_pass_reverification(self):
  from daily_pipeline import reverify_archives
  from unittest.mock import Mock
  objects=Mock();proofs=self.proofs();proofs['matrixone']['report_date']='2026-10-27'
  with self.assertRaisesRegex(Exception,'identity_mismatch'):reverify_archives(objects,proofs,'2026-10-28')
  objects.verify_object.assert_not_called();objects.verify_object.return_value=False
  with self.assertRaisesRegex(Exception,'verified_archive_missing'):reverify_archives(objects,self.proofs(),'2026-10-28')

class FinalizeContractResumeTests(unittest.TestCase):
 def test_fresh_finalize_and_completed_resume_use_the_same_reduced_contract(self):
  from cloud_daily import finalize_contract_nodes,json_bytes,sha256
  legacy=[{'name':n} for n in ('finalize','osv','details','employee','employee_report','validation')]
  fresh=finalize_contract_nodes({},'repo_finalize',legacy)
  self.assertEqual([n['name'] for n in fresh],['finalize','osv','details','validation'])
  persisted={'repo_finalize':{'status':'completed','input_sha256':sha256(json_bytes(fresh))}}
  self.assertEqual(finalize_contract_nodes(persisted,'repo_finalize',legacy),fresh)
 def test_historical_finalize_keeps_its_original_employee_contract(self):
  from cloud_daily import finalize_contract_nodes,json_bytes,sha256
  legacy=[{'name':n} for n in ('finalize','employee','employee_report','validation')]
  persisted={'repo_finalize':{'status':'completed','input_sha256':sha256(json_bytes(legacy))}}
  self.assertEqual(finalize_contract_nodes(persisted,'repo_finalize',legacy),legacy)
 def test_unknown_or_unbound_executed_contract_blocks_resume(self):
  from cloud_daily import finalize_contract_nodes
  for state in ({'status':'completed','input_sha256':'bad'}, {'status':'running','execution_id':'x'}):
   with self.assertRaisesRegex(Exception,'workflow_resume_input_changed'):
    finalize_contract_nodes({'repo_finalize':state},'repo_finalize',[{'name':'employee'}])
 def test_unsubmitted_planned_stage_selects_the_fresh_contract(self):
  from cloud_daily import finalize_contract_nodes
  self.assertEqual(finalize_contract_nodes({'repo_finalize':{'status':'planned'}},'repo_finalize',[{'name':'osv'},{'name':'employee'}]),[{'name':'osv'}])


class EmployeeEvidenceSummaryTests(unittest.TestCase):
 def scan(self):
  return dict(commit='f8478038'+'a'*32,facts=dict(report_date_shanghai='2026-10-28',
   repository='matrixorigin/matrixone',branch='main',commit='f8478038'+'a'*32,
   marker='MATRIX-MINIO-FULLZIP-20261028-MATRIXONE-F8478038',input_files=13,
   queried_package_versions=316,priority_components=[dict(name='golang.org/x/crypto',
    versions={'0.51.0':[]},vulnerability_ids=['GO-example'])]))
 def test_native_evidence_summary_uses_scan_facts_and_exact_marker(self):
  from cloud_daily import employee_evidence_summary
  osv=self.scan();osv['employee_draft']='Unfinished reasoning. Truncated output.'
  raw=employee_evidence_summary(osv);text=raw.decode()
  self.assertTrue(text.endswith(osv['facts']['marker']+'-EMPLOYEE\n'))
  self.assertIn('golang.org/x/crypto：0.51.0',text);self.assertIn('316',text)
  self.assertNotIn('Unfinished',text);self.assertNotIn('修复完成',text)
 def test_wrong_batch_marker_or_commit_is_rejected(self):
  from cloud_daily import employee_evidence_summary
  for field in ('marker','commit'):
   osv=self.scan();osv['facts'][field]='wrong'
   with self.assertRaisesRegex(Exception,'facts_identity_mismatch'):employee_evidence_summary(osv)

class KnowledgeProjectionRecoveryBudgetTests(unittest.TestCase):
 def test_same_source_projection_can_recover_after_three_minutes(self):
  import types
  job=Job(types.SimpleNamespace(data=lambda x:x,request=lambda *a,**k:{'items':[]}))
  job.state['knowledge_registration']={'fid':{'missing_runtime_first_observed_epoch':100}}
  failed=dict(source_file_id='fid',ingest_status='failed',error='workflow execution 213472d9-decc-4bf1-b52f-6306c74360a8 not found: domain object not found')
  with patch.object(kb,'rows',side_effect=[[failed],[dict(source_file_id='fid',ingest_status='succeeded')]]),patch.object(kb.time,'time',return_value=400),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='same.md')])
  self.assertTrue(job.state['knowledge_registration']['fid']['succeeded'])
  self.assertNotIn('append_attempted',job.state['knowledge_registration']['fid'])
 def test_projection_budget_remains_bounded_and_cannot_accept_failure(self):
  import types
  job=Job(types.SimpleNamespace(data=lambda x:x,request=lambda *a,**k:{'items':[]}))
  job.state['knowledge_registration']={'fid':{'active_dispatch_first_observed_epoch':100}}
  failed=dict(source_file_id='fid',ingest_status='failed',error='workflow has an active volume dispatch job: job 213472d9-decc-4bf1-b52f-6306c74360a8 status running')
  with patch.object(kb,'rows',return_value=[failed]),patch.object(kb.time,'time',return_value=701):
   with self.assertRaisesRegex(ValueError,'requires_backend_repair'):kb.ensure_sources(job,[dict(file_id='fid',name='same.md')])
  self.assertNotIn('succeeded',job.state['knowledge_registration']['fid'])

 def test_registration_checkpoint_failure_does_not_claim_submission(self):
  class API:
   def __init__(self):self.appends=0
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    if path.endswith('/sources'):self.appends+=1
    return {'items':[]}
  api=API();job=Job(api);failed=[]
  def save():
   if job.state.get('knowledge_registration',{}).get('fid',{}).get('append_attempted') and not failed:
    failed.append(True);raise TimeoutError()
  job.journal.save=save
  def inventory(*args):return [dict(source_file_id='fid',ingest_status='succeeded')] if api.appends else []
  with patch.object(kb,'rows',side_effect=inventory),patch.object(kb.time,'sleep'):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')])
  self.assertEqual(api.appends,1);self.assertTrue(failed)
 def selection_recovery_fixture(self,preview=None,fail=False):
  class API:
   def __init__(self):self.requests=[];self.registered=False
   @staticmethod
   def data(x):return x
   def request(self,path,payload=None,**kw):
    if path.endswith('/preview'):return preview if preview is not None else dict(file_count=1,table_count=0,total_count=1)
    if path.endswith('/sources'):
     self.requests.append(payload)
     if fail:raise TimeoutError()
     self.registered=True
    return {'items':[]}
  api=API();job=Job(api);job.state['knowledge_registration']={'fid':{'append_attempted':True}}
  return api,job
 def test_missing_legacy_registration_uses_deduplicated_exact_file_selection(self):
  api,job=self.selection_recovery_fixture()
  def inventory(*args):return [dict(source_file_id='fid',ingest_status='succeeded')] if api.registered else []
  with patch.object(kb,'rows',side_effect=inventory),patch.object(kb.time,'sleep'),patch.object(kb.time,'monotonic',side_effect=range(0,100000,20)):
   kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],registration_volume_id=140002)
  self.assertEqual(api.requests,[{'source_selections':[dict(kind='volume_files',volume_id=140002,all_selected=False,selected_file_ids=['fid'])]}])
  self.assertTrue(job.state['knowledge_registration']['fid']['succeeded'])
 def test_selection_recovery_rejects_broader_preview(self):
  api,job=self.selection_recovery_fixture(dict(file_count=2,table_count=0,total_count=2))
  with patch.object(kb,'rows',return_value=[]),patch.object(kb.time,'sleep'),patch.object(kb.time,'monotonic',side_effect=range(0,100000,20)):
   with self.assertRaisesRegex(ValueError,'preview_identity_invalid'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],registration_volume_id=140002)
  self.assertEqual(api.requests,[])
 def test_existing_source_fact_is_not_registered_again(self):
  api,job=self.selection_recovery_fixture(dict(file_count=0,table_count=0,total_count=0))
  with patch.object(kb,'rows',return_value=[]),patch.object(kb.time,'sleep'),patch.object(kb.time,'monotonic',side_effect=range(0,100000,20)):
   with self.assertRaisesRegex(ValueError,'ingestion_deadline'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],deadline_seconds=1000,registration_volume_id=140002)
  self.assertEqual(api.requests,[])
 def test_uncertain_selection_recovery_is_not_repeated(self):
  api,job=self.selection_recovery_fixture(fail=True)
  with patch.object(kb,'rows',return_value=[]),patch.object(kb.time,'sleep'),patch.object(kb.time,'monotonic',side_effect=range(0,100000,20)):
   with self.assertRaisesRegex(ValueError,'uncertain_no_resubmit'):
    kb.ensure_sources(job,[dict(file_id='fid',name='x.md')],registration_volume_id=140002)
  self.assertEqual(len(api.requests),1)

if __name__=='__main__':unittest.main()
