import io
import json
import unittest
from email.message import Message
from urllib.error import HTTPError
from unittest.mock import patch
import gov_auto as a
from test_gov_auto import historical_manifest, fixture, ENV, PROOF

class Reply(io.BytesIO):
    status=200
    def __init__(self,url,data):
        super().__init__(json.dumps(data).encode()); self.url=url
    def geturl(self): return self.url

class Opener:
    def __init__(self,data=None,status=None,headers=None):
        self.data=data; self.status=status; self.headers=headers or Message(); self.calls=[]
    def open(self,req,timeout):
        self.calls.append(req)
        if self.status: raise HTTPError(req.full_url,self.status,'synthetic private detail',self.headers,None)
        return Reply(req.full_url,self.data)

class HTTPTests(unittest.TestCase):
    def test_public_read_no_credentials(self):
        o=Opener({'ok':True}); self.assertEqual(a.read_json(a.old.REPO,'pulls/416','candidate',opener=o),{'ok':True})
        self.assertEqual(o.calls[0].method,'GET'); self.assertIsNone(o.calls[0].get_header('Authorization'))
    def test_governance_token_only_fixed_route(self):
        o=Opener({'ok':True}); a.read_json(a.GOV,'branches/main','governance','synthetic',o)
        self.assertEqual(o.calls[0].get_header('Authorization'),'Bearer synthetic')
        for path in ('pulls/416','branches/other','branches/main?extra=1'):
            with self.assertRaises(a.Hold):a.read_json(a.GOV,path,'governance','synthetic',o)
        self.assertEqual(len(o.calls),1)
    def test_reject_arbitrary_candidate_path(self):
        o=Opener({})
        for path in ('../other','check-runs','actions/runs?url=https://example.invalid','pulls/416?extra=1'):
            with self.assertRaises(a.Hold):a.read_json(a.old.REPO,path,'candidate',opener=o)
        self.assertEqual(o.calls,[])
    def test_http_diagnostic_sanitizes_and_routes(self):
        m=historical_manifest(); h=Message(); h['X-RateLimit-Remaining']='0'; h['Retry-After']='untrusted header detail'
        for status in (401,403,429):
            with self.subTest(status=status):
                o=Opener(status=status,headers=h)
                r=a.public_plan(m,lambda path:a.read_json(a.old.REPO,path,'candidate',opener=o))
                self.assertEqual(r['decision'],'protected_read'); self.assertFalse(r['release_authorized'])
                self.assertEqual(r['diagnostic'],f'candidate/pulls HTTP {status}; remaining=0; retry_after=unknown'); self.assertEqual(len(o.calls),1)
    def test_other_http_errors_hold(self):
        for status in (404,500,502):
            o=Opener(status=status)
            with self.assertRaises(a.ReadHTTP):a.public_plan(historical_manifest(),lambda path:a.read_json(a.old.REPO,path,'candidate',opener=o))
            self.assertEqual(len(o.calls),1)
    def test_policy_failure_not_fallback(self):
        m=historical_manifest(); d=fixture(m); d['pulls/416']['head']['sha']='wrong'
        with self.assertRaises(a.Hold):a.public_plan(m,d.__getitem__)
    def test_protected_read_scope_and_revocation(self):
        m=historical_manifest(); d=fixture(m); calls=[]; scope={'total_count':1,'repositories':[{'id':a.old.RID,'full_name':a.old.REPO}]}
        def request(method,path,token,body=None):
            calls.append((method,path)); return scope if method=='GET' else None
        def probe(credential,observed):
            try:observed('GET','/installation/repositories?per_page=100','synthetic-read')
            finally:observed('DELETE','/installation/token','synthetic-read')
            return PROOF.copy()
        p=a.payload(m,'46044433279');p.update(external_id='GOV-ADMISSION-04:'+m['head']+':46044433279',id=140661146635,app={'id':a.APP})
        key='commits/'+m['head']+'/check-runs?per_page=100&filter=all'
        d[key]['check_runs'].append(p);d[key]['total_count']+=1
        self.assertEqual(a.protected_plan(m,'synthetic',probe,request,lambda token:d.__getitem__)['decision'],'already')
        self.assertEqual(calls[-1],('DELETE','/installation/token'));self.assertEqual(len(calls),2)
        calls.clear();scope['total_count']=2
        with self.assertRaises(a.Hold):a.protected_plan(m,'synthetic',probe,request,lambda token:self.fail('scope failed'))
        self.assertEqual(calls[-1],('DELETE','/installation/token'))
    def test_protected_read_rejects_missing_proof(self):
        with self.assertRaises(a.Hold):a.protected_plan(historical_manifest(),'synthetic',lambda *args:{},lambda *args:None,lambda token:self.fail('unverified'))
    def test_governance_identity_rechecked(self):
        env=dict(ENV,GOV_READ_TOKEN='synthetic')
        with patch.object(a,'read_json',return_value={'name':'main','protected':True,'commit':{'sha':env['GITHUB_SHA']}}) as get:
            a.current_governance(env); get.assert_called_once_with(a.GOV,'branches/main','governance','synthetic')
        with patch.object(a,'read_json',return_value={'name':'main','protected':False,'commit':{'sha':env['GITHUB_SHA']}}):
            with self.assertRaises(a.Hold):a.current_governance(env)

if __name__=='__main__':unittest.main(verbosity=2)
