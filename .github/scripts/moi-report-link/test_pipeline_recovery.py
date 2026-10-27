import copy,hashlib,json,types,unittest,xml.etree.ElementTree as ET
from unittest.mock import patch
from resilient_storage import Objects, PART_SIZE, sha256
from kimi_recovery import run_review
from test_workflow_lifecycle import WorkflowLifecycleTests

class Storage(Objects):
 def __init__(self,lost_part=False,lost_complete=False):
  self.parts={};self.raw=None;self.meta=None;self.lost_part=lost_part;self.lost_complete=lost_complete;self.uploads=0;self.part_puts=[];self.completed=0
 def call(self,method,key,raw=None,headers=None,response_limit=None,timeout=None,query=None):
  if query and 'uploads' in query:
   self.uploads+=1;self.meta=headers['x-amz-meta-sha256'];return 200,{},b'<Result><UploadId>upload-1</UploadId></Result>'
  if query and 'partNumber' in query:
   number=int(query['partNumber']);self.parts[number]=raw;self.part_puts.append(number)
   if self.lost_part:self.lost_part=False;raise TimeoutError()
   return 200,{'ETag':'"'+hashlib.md5(raw,usedforsecurity=False).hexdigest()+'"'},b''
  if query and method=='GET':
   root=ET.Element('ListPartsResult');ET.SubElement(root,'IsTruncated').text='false'
   for n,part in self.parts.items():
    item=ET.SubElement(root,'Part');ET.SubElement(item,'PartNumber').text=str(n);ET.SubElement(item,'Size').text=str(len(part));ET.SubElement(item,'ETag').text='"'+hashlib.md5(part,usedforsecurity=False).hexdigest()+'"'
   return 200,{},ET.tostring(root)
  if query and method=='POST':
   self.raw=b''.join(self.parts[n] for n in sorted(self.parts));self.completed+=1
   if self.lost_complete:self.lost_complete=False;raise TimeoutError()
   return 200,{},b'<CompleteMultipartUploadResult/>'
  if method=='HEAD':
   if self.raw is None:raise RuntimeError('minio_http_404')
   return 200,{'Content-Length':str(len(self.raw)),'X-Amz-Meta-Sha256':self.meta},b''
  if method=='GET':return 200,{},self.raw
  raise AssertionError(method)

class Job:
 def __init__(self,api):
  self.state={'prefix':'test/unique','commits':{'repo':'a'*40}};self.api=api;self.stored={};self.saves=0;self.journal=types.SimpleNamespace(save=self.save)
 def save(self):self.saves+=1
 def store(self,key,value):self.stored[key]=copy.deepcopy(value)
 def issue(self,*args):pass
class Model:
 def __init__(self,replies):self.replies=list(replies);self.requests=[]
 def rpc(self,method,params,rid):
  self.requests.append((method,copy.deepcopy(params),rid));value=self.replies.pop(0)
  if isinstance(value,Exception):raise value
  return copy.deepcopy(value)
def task(state,reason=None,id='t1'):return dict(id=id,status={'state':state},metadata={'reason_display':{'i18n_key':reason}})

class RecoveryTests(unittest.TestCase):
 def test_semantic_parser_failure_persists_terminal_clock_before_restart(self):
  class PersistentJob(Job):
   def save(self):
    super().save();self.persisted=copy.deepcopy(self.state)
  api=Model([task('completed'),task('completed'),task('completed')]);job=PersistentJob(api)
  def reject(t):raise ValueError('focus_quote_mismatch')
  with patch('kimi_recovery.time.time',return_value=100):
   with self.assertRaisesRegex(ValueError,'attempts_exhausted'):
    run_review(job,'repo','primary','source','prompt',reject,max_attempts=2,poll_seconds=0)
  original=job.persisted['model_tasks']['repo_primary']['attempts'][0]
  self.assertEqual(original['seconds'],0);self.assertIn('terminal_observed_at_utc',original)
  restarted=PersistentJob(api);restarted.state=copy.deepcopy(job.persisted)
  with patch('kimi_recovery.time.time',return_value=10000):
   self.assertEqual(run_review(restarted,'repo','primary','source','prompt',lambda t:t['id'],poll_seconds=0),'t1')
  restored=restarted.state['model_tasks']['repo_primary']['attempts'][0]
  self.assertEqual(restored['seconds'],original['seconds'])
  self.assertEqual(restored['terminal_observed_at_utc'],original['terminal_observed_at_utc'])
  self.assertEqual([r[0] for r in api.requests],['message/send','message/send','tasks/get'])

 def test_semantic_validation_failure_retries_same_context_with_new_kimi_task(self):
  api=Model([task('completed'),task('completed',id='t2')]);job=Job(api)
  def reject_once(t):
   if t['id']=='t1':raise ValueError('rag_marker_missing')
   return t['id']
  self.assertEqual(run_review(job,'repo','audit','source','prompt',reject_once,max_attempts=2,poll_seconds=0),'t2')
  saved=job.state['model_tasks']['repo_audit']
  self.assertEqual([r[0] for r in api.requests],['message/send','message/send'])
  self.assertNotEqual(api.requests[0][2],api.requests[1][2])
  self.assertEqual(saved['attempts'][0]['recovery_reason'],'semantic_validation')
  self.assertEqual(saved['attempts'][0]['parser_error'],'rag_marker_missing')

 def test_expired_semantic_revalidation_starts_bounded_new_attempt(self):
  api=Model([task('completed'),task('completed'),task('completed',id='t2')]);job=Job(api)
  def reject(t):
   if t['id']=='t1':raise ValueError('rag_sources_not_selected')
   return t['id']
  with patch('kimi_recovery.time.time',return_value=100):
   with self.assertRaisesRegex(ValueError,'attempts_exhausted'):
    run_review(job,'repo','audit','source','prompt',reject,max_attempts=1,poll_seconds=0)
  with patch('kimi_recovery.time.time',return_value=10000):
   self.assertEqual(run_review(job,'repo','audit','source','prompt',reject,max_attempts=2,poll_seconds=0),'t2')
  self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get','message/send'])
  self.assertEqual(len(job.state['model_tasks']['repo_audit']['attempts']),2)

 def test_successful_primary_can_be_reused_after_its_original_deadline(self):
  api=Model([task('completed'),task('completed')]);job=Job(api)
  run_review(job,'repo','primary','source','prompt',lambda t:t['id'],poll_seconds=0)
  job.state['model_tasks']['repo_primary']['started_epoch']=0
  self.assertEqual(run_review(job,'repo','primary','source','prompt',lambda t:t['id'],poll_seconds=0),'t1')
  self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])
 def test_expired_working_task_only_gets_one_read_and_no_new_inference(self):
  api=Model([task('completed'),task('working')]);job=Job(api)
  run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  job.state['model_tasks']['repo_primary']['started_epoch']=0
  with self.assertRaisesRegex(ValueError,'deadline_exceeded'):
   run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])
 def test_parser_fix_revalidates_completed_task_after_budget_without_new_inference(self):
  api=Model([task('completed'),task('completed')]);job=Job(api)
  def old_parser(t):raise json.JSONDecodeError('Old transport duplication','',0)
  with self.assertRaisesRegex(ValueError,'attempts_exhausted'):
   run_review(job,'repo','primary','source','prompt',old_parser,max_attempts=1,poll_seconds=0)
  saved=job.state['model_tasks']['repo_primary'];original_seconds=saved['attempts'][0]['seconds'];saved['started_epoch']=0
  result=run_review(job,'repo','primary','source','prompt',lambda t:t['id'],max_attempts=1,poll_seconds=0)
  self.assertEqual(result,'t1');self.assertEqual([r[0] for r in api.requests],['message/send','tasks/get'])
  self.assertEqual(len(saved['attempts']),1);self.assertEqual(saved['attempts'][0]['seconds'],original_seconds)
  self.assertEqual(saved['attempts'][0]['recovery_reason'],'invalid_json');self.assertTrue(saved['attempts'][0]['output_revalidated_without_inference'])

 def test_lost_initiation_reuses_exact_upload(self):
  class LostInitiation(Storage):
   def call(self,method,key,*args,**kwargs):
    if kwargs.get('query',{}).get('uploads')=='':
     if method=='GET':return 200,{},b'<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>new.zip</Key><UploadId>upload-1</UploadId></Upload></ListMultipartUploadsResult>'
     super().call(method,key,*args,**kwargs);raise TimeoutError()
    return super().call(method,key,*args,**kwargs)
  store=LostInitiation();raw=b'z'*(PART_SIZE+1);state={}
  store.put_verified('new.zip',raw,sha256(raw),state,lambda:None)
  self.assertEqual(store.uploads,1);self.assertEqual(state['upload_id'],'upload-1');self.assertEqual(store.raw,raw)
 def test_uncertain_small_artifact_put_readback_prevents_duplicate(self):
  class Uncertain(Objects):
   def __init__(self):self.writes=0;self.raw=None
   def call(self,method,key,raw=None,*args,**kwargs):
    if method=='PUT':self.writes+=1;self.raw=raw;raise TimeoutError()
    return 200,{},self.raw
  store=Uncertain();result=store.publish('receipt.json',b'bytes','application/json')
  self.assertEqual(store.writes,1);self.assertTrue(result['readback_verified'])
 def test_archive_commit_is_frozen_before_upload_and_resume(self):
  import archive_transfer as transfer
  class Memory:
   def __init__(self):self.data={};self.verified=False;self.fail=True
   def call(self,method,key):
    if key not in self.data:raise RuntimeError('minio_http_404')
    return 200,{},self.data[key]
   def publish(self,key,raw,kind):self.data[key]=raw
   def verify_object(self,*args):return self.verified
   def put_verified(self,key,raw,digest,state,save):
    saved=json.loads(next(raw for key,raw in self.data.items() if '/acquisition-' in key))
    assert saved['commit']=='a'*40 and saved['proof']['sha256']==sha256(raw)
    if self.fail:self.fail=False;raise TimeoutError()
    self.verified=True
  class GitHub:
   def __init__(self):self.branches=0
   def get(self,repo,path,binary=False):
    if '/branches/' in path:self.branches+=1;return {'commit':{'sha':('a' if self.branches==1 else 'b')*40}}
    return b'fixed-code'
  import tempfile
  store=Memory();github=GitHub();repo=types.SimpleNamespace(owner='owner',name='repo',branch='main')
  validate=lambda stream,commit:dict(commit=commit,bytes=10,sha256=sha256(b'fixed-code'),manifests=[])
  with tempfile.TemporaryDirectory() as tmp,patch.object(transfer.tempfile,'gettempdir',return_value=tmp):
   with self.assertRaises(TimeoutError):transfer.prepare(github,store,repo,'test','2026-10-25',validate,ValueError)
   proof=transfer.prepare(github,store,repo,'test','2026-10-25',validate,ValueError)
  self.assertEqual(github.branches,1);self.assertEqual(proof['commit'],'a'*40)
 def test_lost_part_and_completion_responses_reconcile(self):
  store=Storage(True,True);raw=b'x'*(PART_SIZE+123);state={};store.put_verified('new.zip',raw,sha256(raw),state,lambda:None)
  self.assertEqual(store.raw,raw);self.assertEqual(state['status'],'verified');self.assertEqual(store.part_puts,[1,2]);self.assertEqual(store.completed,1)
  store.put_verified('new.zip',raw,sha256(raw),state,lambda:None);self.assertEqual(store.uploads,1)
 def test_restart_reuses_remote_part(self):
  store=Storage();raw=b'x'*(PART_SIZE+123);store.meta=sha256(raw);store.parts[1]=raw[:PART_SIZE]
  store.put_verified('new.zip',raw,sha256(raw),{'upload_id':'upload-1','status':'uploading','parts':{}},lambda:None)
  self.assertEqual(store.part_puts,[2]);self.assertEqual(store.uploads,0)
 def test_conflicting_part_blocks_completion(self):
  store=Storage();raw=b'x'*(PART_SIZE+123);store.parts[1]=b'bad'
  with self.assertRaisesRegex(ValueError,'identity_conflict'):store.put_verified('new.zip',raw,sha256(raw),{'upload_id':'upload-1','parts':{}},lambda:None)
  self.assertEqual(store.completed,0)
 def test_stream_failure_uses_new_attempt_and_preserves_failure(self):
  bad=task('input-required','reason.agent_runtime.finish.stream_transport');api=Model([bad,task('completed',id='t2')]);job=Job(api)
  self.assertEqual(run_review(job,'repo','primary','source','prompt',lambda t:t['id'],poll_seconds=0),'t2')
  self.assertEqual(len(job.state['model_tasks']['repo_primary']['attempts']),2);self.assertNotEqual(api.requests[0][2],api.requests[1][2]);self.assertTrue(any('attempt-1-task' in k for k in job.stored))
 def test_request_timeout_reuses_identical_message(self):
  api=Model([TimeoutError(),task('completed')]);job=Job(api);run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  self.assertEqual(api.requests[0],api.requests[1]);self.assertEqual(len(job.state['model_tasks']['repo_primary']['attempts']),1)
 def test_poll_timeout_reuses_task(self):
  api=Model([task('working'),TimeoutError(),task('completed')]);job=Job(api);run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  self.assertEqual([x[0] for x in api.requests],['message/send','tasks/get','tasks/get']);self.assertEqual(api.requests[1][1],api.requests[2][1])
 def test_recovery_is_bounded(self):
  bad=task('input-required','reason.agent_runtime.finish.stream_transport');api=Model([bad,bad,bad]);job=Job(api)
  with self.assertRaisesRegex(ValueError,'attempts_exhausted'):run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  self.assertEqual(len(api.requests),3)
 def test_other_input_required_never_retried(self):
  api=Model([task('input-required','reason.agent_runtime.finish.authentication')]);job=Job(api)
  with self.assertRaisesRegex(ValueError,'nonrecoverable'):run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  self.assertEqual(len(api.requests),1)
 def test_contract_change_on_resume_blocks(self):
  api=Model([task('completed')]);job=Job(api);run_review(job,'repo','primary','source','prompt',lambda t:t,poll_seconds=0)
  with self.assertRaisesRegex(ValueError,'contract_changed'):run_review(job,'repo','primary','source','changed',lambda t:t,poll_seconds=0)
 def test_metadata_text_is_not_enough_to_accept(self):
  from api_port_review import parse_review
  bad=task('completed');bad['artifacts']=[{'parts':[{'kind':'text','text':'{}'}]}]
  with self.assertRaises(ValueError):parse_review(bad,'repo','a'*40)
if __name__=='__main__':unittest.main()
