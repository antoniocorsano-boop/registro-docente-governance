import copy, io, json, unittest
from unittest.mock import patch
import emitter as e
import verify_remote as v
from test_remote import fixture

CTX={'GITHUB_REPOSITORY':e.GOV,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
     'GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_REF':e.GOV+'/'+e.EMIT_WORKFLOW+'@refs/heads/main',
     'GOV_ADMISSION_MODE':'live','GITHUB_RUN_ID':'123456'}
SCOPE={'total_count':1,'repositories':[{'id':v.RID,'full_name':v.REPO}]}
K='commits/'+v.HEAD+'/check-runs?per_page=100&filter=latest'

class TestEmitter(unittest.TestCase):
    def setUp(self):
        self.data=fixture(); self.posts=[]; self.scope=copy.deepcopy(SCOPE)
        self.ctx=CTX.copy(); self.app=e.APP_ID
    def post(self,payload):
        self.posts.append(copy.deepcopy(payload))
        return dict(payload, id=1, app={'id':e.APP_ID})
    def run_emit(self, fetch=None, post=None):
        return e.emit(self.ctx,fetch or self.data.__getitem__,lambda:self.scope,lambda:self.app,post or self.post)
    def denied(self, fetch=None):
        with self.assertRaises((v.Denied,KeyError,OSError,ValueError,TypeError)): self.run_emit(fetch)
        self.assertEqual(self.posts,[])
    def test_exact_emission(self):
        self.assertEqual(self.run_emit(),{'state':'CHECK_EMITTED','check_id':1,'candidate':v.HEAD,'release_authorized':False})
        self.assertEqual(len(self.posts),1)
        self.assertEqual(self.posts[0]['name'],e.CHECK)
        self.assertEqual(self.posts[0]['head_sha'],v.HEAD)
        self.assertEqual(self.posts[0]['conclusion'],'success')
        self.assertNotIn('merge',self.posts[0].keys())
    def test_wrong_context(self):
        for key in CTX:
            with self.subTest(key=key):
                self.ctx=CTX.copy(); self.ctx[key]='invalid'; self.denied()
    def test_wrong_app_before_post(self):
        self.app=0; self.denied()
    def test_scope_empty(self):
        self.scope={'total_count':0,'repositories':[]}; self.denied()
    def test_scope_extra(self):
        self.scope['repositories'].append({'id':0,'full_name':'other/repo'}); self.scope['total_count']=2; self.denied()
    def test_scope_wrong_id(self):
        self.scope['repositories'][0]['id']=0; self.denied()
    def test_scope_wrong_name(self):
        self.scope['repositories'][0]['full_name']='other/repo'; self.denied()
    def test_candidate_changed(self):
        self.data['pulls/416']['head']['sha']='other'; self.denied()
    def test_base_changed(self):
        self.data['branches/main']['commit']['sha']='other'; self.denied()
    def test_no_protection(self):
        self.data['branches/main']['protected']=False; self.denied()
    def test_missing_job(self):
        self.data['actions/runs/45937846157/jobs?per_page=100']['jobs'].pop(); self.denied()
    def test_skipped_job(self):
        self.data['actions/runs/45937846157/jobs?per_page=100']['jobs'][0]['conclusion']='skipped'; self.denied()
    def test_wrong_workflow_app(self):
        self.data[K]['check_runs'][0]['app']['id']=0; self.denied()
    def test_existing_attestation_any_source(self):
        self.data[K]['check_runs'].append(dict(name=e.CHECK,app={'id':0})); self.data[K]['total_count']+=1; self.denied()
    def test_final_race(self):
        count=0
        def get(p):
            nonlocal count
            if p=='pulls/416':
                count+=1
                if count==3: self.data[p]['head']['sha']='other'
            return self.data[p]
        self.denied(get)
    def test_api_unavailable(self):
        def get(p): raise OSError('synthetic')
        self.denied(get)
    def test_wrong_result(self):
        with patch.object(e,'verify',return_value=dict(e.EXPECTED,jobs=22)): self.denied()
    def test_post_response_wrong_source(self):
        def post(p): return dict(self.post(p),app={'id':0})
        with self.assertRaises(v.Denied): self.run_emit(post=post)
        self.assertEqual(len(self.posts),1)
    def test_post_response_wrong_sha(self):
        def post(p): return dict(self.post(p),head_sha='other')
        with self.assertRaises(v.Denied): self.run_emit(post=post)
        self.assertEqual(len(self.posts),1)
    def test_post_ambiguous_no_retry(self):
        def post(p): self.posts.append(p); raise OSError('synthetic timeout')
        with self.assertRaises(OSError): self.run_emit(post=post)
        self.assertEqual(len(self.posts),1)

class Response(io.BytesIO):
    def __init__(self,url,status,body): super().__init__(json.dumps(body).encode()); self.url=url; self.status=status
    def geturl(self): return self.url
class FakeOpener:
    def __init__(self): self.calls=[]; self.redirect=False; self.status=None
    def open(self,req,timeout):
        self.calls.append(req)
        return Response('https://example.invalid/' if self.redirect else req.full_url,self.status or (201 if req.method=='POST' else 200),{})
class TestTransport(unittest.TestCase):
    def setUp(self): self.op=FakeOpener(); self.t=e.InstallationTransport('synthetic-not-a-token',self.op)
    def payload(self):
        return {'name':e.CHECK,'head_sha':v.HEAD,'status':'completed','conclusion':'success','external_id':'GOV-ADMISSION-04:'+v.HEAD+':123456','details_url':'https://github.com/'+e.GOV+'/actions/runs/123456','output':{'title':'Independent exact-candidate evidence verified','summary':'12 workflows, 23 jobs; evidence only. Not a merge or release authorization.'}}
    def test_fixed_get(self):
        self.t.fetch('pulls/416'); q=self.op.calls[0]
        self.assertEqual(q.full_url,'https://api.github.com/repos/'+v.REPO+'/pulls/416'); self.assertEqual(q.method,'GET')
    def test_scope_endpoint(self):
        self.t.scope(); self.assertEqual(self.op.calls[0].full_url,'https://api.github.com/installation/repositories?per_page=100')
    def test_fixed_post(self):
        self.t.post(self.payload()); self.assertEqual(self.op.calls[0].method,'POST'); self.assertTrue(self.op.calls[0].full_url.endswith('/check-runs'))
    def test_reject_other_route(self):
        with self.assertRaises(v.Denied): self.t._request('POST','/repos/other/repo/check-runs',{})
        self.assertEqual(self.op.calls,[])
    def test_reject_traversal(self):
        with self.assertRaises(v.Denied): self.t.fetch('../other')
        self.assertEqual(self.op.calls,[])
    def test_reject_redirect(self):
        self.op.redirect=True
        with self.assertRaises(v.Denied): self.t.scope()
    def test_reject_status(self):
        self.op.status=202
        with self.assertRaises(v.Denied): self.t.post(self.payload())
    def test_reject_arbitrary_check(self):
        p=self.payload(); p['name']='other'
        with self.assertRaises(v.Denied): self.t.post(p)
        self.assertEqual(self.op.calls,[])
    def test_reject_other_sha(self):
        p=self.payload(); p['head_sha']='other'
        with self.assertRaises(v.Denied): self.t.post(p)
        self.assertEqual(self.op.calls,[])
    def test_empty_token(self):
        with self.assertRaises(v.Denied): e.InstallationTransport('',self.op)
if __name__=='__main__': unittest.main(verbosity=2)
