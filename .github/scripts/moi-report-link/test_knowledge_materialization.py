import copy,hashlib,types,unittest
from unittest.mock import patch
import knowledge_gate as gate
from knowledge_materialization import verify,document_segments


class MaterializationTests(unittest.TestCase):
    def fixture(self):
        fid='same-original-fid';eid='same-original-execution';sid='same-original-source'
        raw=b'MATRIX-MINIO-FULLZIP-20261102-TAAS-F79D270A-DETAIL'
        artifact=dict(file_id=fid,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        target=dict(file_id=fid,marker=raw.decode())
        found=[dict(source_id=sid,source_file_id=fid,kb_file_id=fid,ingest_status='pending',error=None)]
        fact=dict(file_id=fid,execution_id=eid,workflow_id=gate.KB_WORKFLOW_ID,status='completed',execution_mode='volume_trigger')
        execution=dict(fact,input_payload=dict(file_id=fid,volume_id=140002))
        node=dict(node=dict(node_key='root.register_lineage'),run=dict(status='COMPLETED',runtime_input=dict(source_file_ids=[fid],vector_table='kb_80001_text_index'),runtime_output=dict(vector_asset_id='vector-1',lineages=[dict(source_file_id=fid,vector_asset_id='vector-1')])))
        doc=dict(source=dict(model_id=80001,source_id=sid,source_file_id=fid,kb_file_id=fid,effective_enabled=True),preview=dict(available=True),etag='snapshot-1',segment_status=dict(available=True,total=1),segments=[dict(segment_id='segment-1',enabled=True,chunk_id='chunk-1',content=raw.decode(),metadata=dict(volume_id='140002'))])
        self.calls=[];self.facts=[fact];self.execution=execution;self.node=node;self.doc=doc;self.raw=raw
        def request(path,payload=None,**kw):
            self.assertIsNone(payload);self.assertFalse(kw['retry']);self.assertLessEqual(kw['timeout'],30 if path.startswith('/semantic-models/80001/sources?') else 15);self.calls.append(path)
            if path.endswith('/file-executions?file_id='+fid):return dict(executions=self.facts,total=len(self.facts))
            if path.endswith('/executions/'+eid):return dict(execution=self.execution)
            if path.endswith('/nodes/root.register_lineage'):return self.node
            if path.endswith('/'+sid+'/document'):return self.doc
            if path.startswith('/semantic-models/80001/sources?'):return dict(items=found)
            raise AssertionError(path)
        api=types.SimpleNamespace(request=request,data=lambda v:v,file=lambda f:self.raw)
        self.saved=[]
        state=dict(prefix='same-batch',knowledge_registration={fid:dict(ingestion_deadline_epoch=1)})
        job=types.SimpleNamespace(api=api,state=state,journal=types.SimpleNamespace(save=lambda:self.saved.append(copy.deepcopy(state))))
        return job,artifact,target,found

    def test_actual_completed_ingestion_can_be_verified_without_mutation(self):
        job,a,t,f=self.fixture();p=verify(job,a,t,f,140002)
        self.assertEqual(p['original_source_projection'],'pending');self.assertFalse(p['source_projection_repaired'])
        self.assertTrue(p['native_retrieval_and_citation_still_required']);self.assertEqual(len(self.calls),4)
        self.assertEqual(f[0]['ingest_status'],'pending')

    def test_gate_retains_expired_budget_and_requires_later_native_audit(self):
        job,a,t,f=self.fixture()
        with patch.object(gate,'emit'),patch('pipeline_telemetry.emit'):
            gate.ensure_sources(job,[a],registration_volume_id=140002,targets=[t])
        state=job.state['knowledge_registration'][a['file_id']]
        self.assertEqual(state['ingestion_deadline_epoch'],1);self.assertNotIn('succeeded',state)
        self.assertTrue(state['materialized_readback']['native_retrieval_and_citation_still_required'])

    def test_active_execution_prevents_acceptance(self):
        job,a,t,f=self.fixture();self.facts.insert(0,dict(self.facts[0],status='running'))
        self.assertIsNone(verify(job,a,t,f,140002));self.assertEqual(len(self.calls),1)

    def test_failed_latest_native_execution_does_not_use_older_success(self):
        job,a,t,f=self.fixture();self.facts.insert(0,dict(self.facts[0],status='failed'))
        self.assertIsNone(verify(job,a,t,f,140002))

    def test_hash_or_document_mismatch_blocks(self):
        for kind in ['hash','source','marker','partial','lineage','execution','disabled']:
            with self.subTest(kind=kind):
                job,a,t,f=self.fixture()
                if kind=='hash':self.raw=b'different'
                if kind=='source':self.doc['source']['source_file_id']='wrong'
                if kind=='marker':self.doc['segments'][0]['content']='wrong'
                if kind=='partial':self.doc['segment_status']['total']=2
                if kind=='lineage':self.node['run']['runtime_output']['lineages']=[]
                if kind=='execution':self.execution['input_payload']['file_id']='wrong'
                if kind=='disabled':self.doc['source']['effective_enabled']=False
                with self.assertRaises(ValueError):verify(job,a,t,f,140002)

    def test_arbitrary_failed_status_or_duplicate_sources_cannot_pass(self):
        job,a,t,f=self.fixture();f[0].update(ingest_status='failed',error='parse failed')
        self.assertIsNone(verify(job,a,t,f,140002));self.assertFalse(self.calls)
        job,a,t,f=self.fixture();f.append(copy.deepcopy(f[0]))
        self.assertIsNone(verify(job,a,t,f,140002));self.assertFalse(self.calls)

    def pages(self):
        self.fixture()
        first=copy.deepcopy(self.doc);last=copy.deepcopy(self.doc)
        first['segments']=[dict(self.doc['segments'][0],segment_id='s'+str(i),chunk_id='c'+str(i),content='first') for i in range(20)]
        last['segments']=[dict(self.doc['segments'][0],segment_id='s'+str(i),chunk_id='c'+str(i)) for i in range(20,114)]
        first['segment_status'].update(total=114,next_cursor='opaque+/=')
        last['segment_status'].update(total=114)
        return first,last

    def test_all_114_segments_use_official_cursor_and_stable_snapshot(self):
        first,last=self.pages();paths=[]
        def read(path):
            paths.append(path);return first if len(paths)==1 else last
        segments,etag,pages=document_segments(read,'same-original-source','same-original-fid')
        self.assertEqual((len(segments),etag,pages),(114,'snapshot-1',2))
        self.assertTrue(paths[1].endswith('?page_size=100&cursor=opaque%2B%2F%3D'))
        self.assertIn(self.raw.decode(),segments[-1]['content'])

    def test_inconsistent_or_partial_pages_fail_closed(self):
        for kind in ['identity','etag','total','duplicate','empty','short','cursor_loop','missing_id','extra_cursor','missing_etag','error']:
            with self.subTest(kind=kind):
                first,last=self.pages()
                if kind=='identity':last['source']['kb_file_id']='wrong'
                if kind=='etag':last['etag']='changed'
                if kind=='total':last['segment_status']['total']=115
                if kind=='duplicate':last['segments'][0]['segment_id']='s0'
                if kind=='empty':last['segments']=[]
                if kind=='short':last['segments']=last['segments'][:-1]
                if kind=='cursor_loop':
                    last['segments']=last['segments'][:1];last['segment_status']['next_cursor']='opaque+/='
                if kind=='missing_id':last['segments'][0].pop('segment_id')
                if kind=='extra_cursor':last['segment_status']['next_cursor']='more'
                if kind=='missing_etag':first.pop('etag')
                def read(path):
                    if '?' not in path:return first
                    if kind=='error':raise ValueError('http_failure')
                    return last
                with self.assertRaises(ValueError):document_segments(read,'same-original-source','same-original-fid')

    def test_pagination_uses_original_bounded_reader(self):
        first,last=self.pages();reads=[]
        def read(path):
            reads.append(path)
            if len(reads)>1:raise ValueError('knowledge_materialization_read_deadline')
            return first
        with self.assertRaisesRegex(ValueError,'read_deadline'):
            document_segments(read,'same-original-source','same-original-fid')
        self.assertEqual(len(reads),2)

if __name__=='__main__':unittest.main()
