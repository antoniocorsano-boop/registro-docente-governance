import copy, io, json, unittest
from unittest.mock import patch
import auth_probe as a
import emitter as e
import verify_remote as v
from test_remote import fixture
from test_auth_probe import Tests as AuthTests
from test_emitter import CTX, SCOPE, K
import integration as i

class Transport:
    def __init__(self,test): self.test=test
    def fetch(self,path): return self.test.data[path]
    def scope(self): return self.test.scope
    def post(self,payload):
        self.test.posts.append(payload)
        if self.test.post_error: raise OSError('synthetic HTTP timeout')
        return dict(payload,id=123,app={'id':a.APP})

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.env=dict(CTX,GITHUB_ACTOR_ID=str(a.OWNER[1]),GITHUB_TRIGGERING_ACTOR=a.OWNER[0],GITHUB_REF_PROTECTED='true',GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40)
        self.auth=AuthTests().fixture(); self.calls=[]; self.posts=[]; self.issues=0; self.data=fixture(); self.scope=copy.deepcopy(SCOPE); self.post_error=False; self.revoke_error=False; self.issue_error=False
        rows=self.auth['/app/installations?per_page=100']; rows[0]['id']=i.INSTALLATION
        self.auth['/repos/'+a.REPO+'/installation']['id']=i.INSTALLATION
        self.auth[f'/app/installations/{i.INSTALLATION}/access_tokens']=self.auth.pop('/app/installations/42/access_tokens')
        self.response={'token':'synthetic-write','permissions':i.WRITE_PERMS.copy()}
    def request(self,m,p,c,b=None):
        self.calls.append((m,p,c,b))
        if m=='DELETE' and c=='synthetic-write' and self.revoke_error: raise OSError('synthetic revoke failure')
        return self.auth[p]
    def issue(self,c):
        self.issues+=1
        if self.issue_error: raise OSError('synthetic issuance failure')
        return self.response
    def execute(self): return i.run(self.env,'synthetic-jwt',self.request,self.issue,lambda token:Transport(self))
    def assert_revoked(self): self.assertEqual(self.calls[-1][:3],('DELETE','/installation/token','synthetic-write'))
    def test_exact(self):
        self.assertEqual(self.execute(),{'state':'CHECK_EMITTED','check_id':123,'candidate':v.HEAD,'release_authorized':False,'token_revoked':True}); self.assertEqual(self.issues,1); self.assertEqual(len(self.posts),1); self.assert_revoked()
    def test_unauthorized_context_before_auth(self):
        for k in self.env:
            with self.subTest(k=k):
                env=self.env.copy(); self.env[k]='invalid'
                with self.assertRaises((i.Hold,v.Denied)):self.execute()
                self.assertEqual(self.calls,[]); self.assertEqual(self.issues,0); self.env=env
    def test_wrong_installation_before_issue(self):
        self.auth['/app/installations?per_page=100'][0]['id']=42
        with self.assertRaises(a.Hold):self.execute()
        self.assertEqual(self.issues,0); self.assertEqual(self.posts,[])
    def test_permission_excess_revokes(self):
        self.response['permissions']['statuses']='write'
        with self.assertRaises(i.Hold):self.execute()
        self.assert_revoked(); self.assertEqual(self.posts,[])
    def test_scope_revokes(self):
        self.scope['total_count']=2
        with self.assertRaises(v.Denied):self.execute()
        self.assert_revoked(); self.assertEqual(self.posts,[])
    def test_wrong_candidate_revokes(self):
        self.data['pulls/416']['head']['sha']='wrong'
        with self.assertRaises(v.Denied):self.execute()
        self.assert_revoked(); self.assertEqual(self.posts,[])
    def test_existing_check_revokes(self):
        self.data[K]['check_runs'].append(dict(name=e.CHECK,app={'id':a.APP})); self.data[K]['total_count']+=1
        with self.assertRaises(v.Denied):self.execute()
        self.assert_revoked(); self.assertEqual(self.posts,[])
    def test_ambiguous_post_no_retry(self):
        self.post_error=True
        with self.assertRaises(OSError):self.execute()
        self.assertEqual(len(self.posts),1); self.assert_revoked()
    def test_revocation_failure_after_post(self):
        self.revoke_error=True
        with self.assertRaisesRegex(i.Hold,'CHECK_EMITTED; WRITE_TOKEN_REVOCATION_UNATTESTED'):self.execute()
        self.assertEqual(len(self.posts),1); self.assert_revoked()
    def test_issue_error_no_retry(self):
        self.issue_error=True
        with self.assertRaisesRegex(i.Hold,'WRITE_TOKEN_ISSUANCE_UNCERTAIN'):self.execute()
        self.assertEqual(self.issues,1); self.assertEqual(self.posts,[])
    def test_synthetic_never_reads_secret_or_signs(self):
        self.env['GOV_ADMISSION_MODE']='synthetic'; self.env['GOV_APP_PRIVATE_KEY']='synthetic'
        with patch.dict(i.os.environ,self.env,clear=True),patch.object(a,'jwt') as sign,patch('builtins.print'):
            with self.assertRaises(SystemExit):i.main()
            sign.assert_not_called(); self.assertEqual(i.os.environ['GOV_APP_PRIVATE_KEY'],'synthetic')
    def test_write_token_narrow_request(self):
        class R(io.BytesIO):
            status=201
            def geturl(self):return 'https://api.github.com/app/installations/186423539/access_tokens'
        class Opener:
            def open(self,req,timeout):
                self.req=req; return R(b'{"synthetic":true}')
        o=Opener(); self.assertEqual(i.issue('synthetic-jwt',o),{'synthetic':True}); self.assertEqual(o.req.method,'POST'); self.assertEqual(json.loads(o.req.data),{'permissions':i.WRITE_PERMS,'repository_ids':[a.RID]}); self.assertNotIn('statuses',i.WRITE_PERMS)

if __name__=='__main__':unittest.main(verbosity=2)
