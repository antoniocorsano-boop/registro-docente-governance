import copy
import unittest
import gov_auto as a

PERMS={'actions':'read','checks':'write','contents':'read','metadata':'read','pull_requests':'read'}
PROOF={'state':'AUTH_SCOPE_PASS','app_id':a.APP,'installation_id':a.INSTALLATION,'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}
ENV={'GITHUB_REPOSITORY':a.GOV,'GITHUB_REF':'refs/heads/main','GITHUB_REF_PROTECTED':'true','GITHUB_EVENT_NAME':'push','GITHUB_RUN_ATTEMPT':'1','GITHUB_ACTOR_ID':a.OWNER,'GITHUB_TRIGGERING_ACTOR':'antoniocorsano-boop','GITHUB_WORKFLOW_REF':a.GOV+'/'+a.WORKFLOW+'@refs/heads/main','GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,'GITHUB_RUN_ID':'1234'}

def fixture(m):
    p={'number':m['pr'],'state':'open','merged':False,'head':{'sha':m['head'],'ref':m['branch'],'repo':{'id':a.old.RID,'full_name':a.old.REPO}},'base':{'sha':m['base'],'ref':'main','repo':{'id':a.old.RID,'full_name':a.old.REPO}}}
    data={'pulls/'+str(m['pr']):p,'branches/main':{'name':'main','commit':{'sha':m['base']},'protected':True},'git/commits/'+m['head']:{'sha':m['head'],'parents':[{'sha':m['parent']}],'tree':{'sha':m['tree']}},'git/trees/'+m['tree']+'?recursive=1':{'sha':m['tree'],'truncated':False,'tree':[{'path':k,'sha':v,'mode':'100644','type':'blob'} for k,v in a.ENTRIES.items()]}}
    runs=[]; checks=[]
    for rid,(wid,names) in a.old.RUNS.items():
        w={'id':rid,'workflow_id':wid,'path':'.github/workflows/'+a.PATHS[wid][0],'head_sha':m['head'],'head_branch':m['branch'],'event':'pull_request','run_attempt':1,'status':'completed','conclusion':'success','repository':{'id':a.old.RID},'head_repository':{'id':a.old.RID},'check_suite_id':rid+1,'pull_requests':[copy.deepcopy(p)]}
        data['actions/runs/'+str(rid)]=w; runs.append(copy.deepcopy(w)); jobs=[]
        for name in names:
            ident=len(checks)+1
            jobs.append({'id':ident,'name':name,'run_id':rid,'head_sha':m['head'],'status':'completed','conclusion':'success'})
            checks.append({'id':ident,'name':name,'app':{'id':a.old.APP},'head_sha':m['head'],'status':'completed','conclusion':'success','check_suite':{'id':rid+1}})
        data['actions/runs/'+str(rid)+'/jobs?per_page=100']={'total_count':len(jobs),'jobs':jobs}
    data['actions/runs?head_sha='+m['head']+'&event=pull_request&per_page=100']={'total_count':len(runs),'workflow_runs':runs}
    for f in ('latest','all'):
        data['commits/'+m['head']+'/check-runs?per_page=100&filter='+f]={'total_count':len(checks),'check_runs':copy.deepcopy(checks)}
    return data

class FakeTransport:
    def __init__(self,test): self.test=test
    def fetch(self,p): return self.test.data[p]
    def scope(self): return self.test.scope
    def post(self,body):
        self.test.posts.append(body)
        if self.test.post_error: raise OSError('synthetic timeout')
        c=dict(body,id=12345,app={'id':a.APP})
        if not self.test.readback_missing: self.test.add_check(c)
        if self.test.reply_wrong: return dict(c,head_sha='wrong')
        return c

class Tests(unittest.TestCase):
    def setUp(self):
        self.m=a.load_manifest(); self.env=ENV.copy(); self.data=fixture(self.m); self.calls=[]; self.posts=[]; self.revoked=[]
        self.scope={'total_count':1,'repositories':[{'id':a.old.RID,'full_name':a.old.REPO}]}; self.proof=PROOF.copy(); self.perms=PERMS.copy()
        self.post_error=False; self.reply_wrong=False; self.readback_missing=False; self.issue_error=False; self.revoke_error=False; self.gov_count=0; self.gov_race=False
    def key(self,f): return 'commits/'+self.m['head']+'/check-runs?per_page=100&filter='+f
    def add_check(self,c):
        for f in ('latest','all'):
            self.data[self.key(f)]['check_runs'].append(copy.deepcopy(c)); self.data[self.key(f)]['total_count']+=1
    def existing(self):
        p=a.payload(self.m,'46044433279'); p['external_id']='GOV-ADMISSION-04:'+self.m['head']+':46044433279'; return dict(p,id=140661146635,app={'id':a.APP})
    def plan(self): return a.plan(self.m,self.data.__getitem__)
    def auth(self,c): self.calls.append('auth'); return self.proof
    def issue(self,c):
        self.calls.append('issue')
        if self.issue_error: raise OSError('synthetic')
        return {'token':'synthetic','permissions':self.perms}
    def revoke(self,t):
        self.revoked.append(t)
        if self.revoke_error: raise OSError('synthetic')
    def governance(self,env):
        self.gov_count+=1
        if self.gov_race and self.gov_count>1: raise a.Hold('governance changed')
    def live(self): return a.execute_live(self.env,self.m,'synthetic',self.auth,self.issue,lambda t:FakeTransport(self),self.revoke,self.governance,PERMS)
    def test_equivalent_to_qualified_verifier(self):
        original=a.old.verify(self.data.__getitem__); new=self.plan(); self.assertEqual((new['candidate'],new['workflows'],new['jobs']),(original['candidate'],original['workflows'],original['jobs'])); self.assertEqual(new['decision'],'ready')
    def test_future_candidate_not_frozen(self):
        self.m.update(pr=500,head='b'*40,base='c'*40,parent='d'*40,tree='e'*40,branch='candidate/next'); self.data=fixture(self.m); self.assertEqual(self.plan()['candidate'],'b'*40)
    def test_context_fail_closed(self):
        for k in ENV:
            with self.subTest(k=k):
                env=ENV.copy();env[k]='invalid'
                with self.assertRaises(a.Hold):a.context(env)
    def test_manifest_fail_closed(self):
        for mutation in [lambda m:m.update(schema=True),lambda m:m.update(policy='wrong'),lambda m:m.update(pr=True),lambda m:m.update(head='bad'),lambda m:m.update(branch='main'),lambda m:m.update(branch='candidate/../bad'),lambda m:m.update(runs=[]),lambda m:m.pop('base')]:
            m=self.m.copy();mutation(m)
            with self.assertRaises(a.Hold):a.manifest(m)
    def test_existing_attestation_no_second_emission(self):
        self.add_check(self.existing()); self.assertEqual(self.plan()['decision'],'already'); self.assertEqual(self.live()['state'],'ALREADY_ATTESTED'); self.assertEqual(self.posts,[]); self.assertEqual(self.revoked,['synthetic'])
    def test_future_attestation_bound_to_policy(self):
        self.m.update(pr=500,head='b'*40,base='c'*40,parent='d'*40,tree='e'*40,branch='candidate/next'); self.data=fixture(self.m)
        self.add_check(dict(a.payload(self.m,'777'),id=88,app={'id':a.APP})); self.assertEqual(self.plan()['decision'],'already')
        self.data=fixture(self.m); self.add_check(self.existing())
        with self.assertRaises(a.Hold):self.plan()
    def test_wrong_policy_attestation(self):
        c=dict(a.payload(self.m,'777'),id=88,app={'id':a.APP});c['external_id']=c['external_id'].replace(a.POLICY,'unknown');self.add_check(c)
        with self.assertRaises(a.Hold):self.plan()
    def test_conflicting_attestation(self):
        c=self.existing(); c['app']['id']=0; self.add_check(c)
        with self.assertRaises(a.Hold):self.plan()
    def test_duplicate_attestation(self):
        self.add_check(self.existing());self.add_check(dict(self.existing(),id=89))
        with self.assertRaises(a.Hold):self.plan()
    def test_wrong_attestation_provenance(self):
        c=self.existing(); c['details_url']='https://example.invalid'; self.add_check(c)
        with self.assertRaises(a.Hold):self.plan()
    def test_wrong_attestation_evidence(self):
        c=self.existing(); c['output']['summary']='different'; self.add_check(c)
        with self.assertRaises(a.Hold):self.plan()
    def test_plan_negative_cases(self):
        m=self.m; c='git/commits/'+m['head']; t='git/trees/'+m['tree']+'?recursive=1'; r='actions/runs?head_sha='+m['head']+'&event=pull_request&per_page=100'; w='actions/runs/45937846094'; j=w+'/jobs?per_page=100'; k=self.key('latest'); p='pulls/'+str(m['pr'])
        variants=[lambda d:d[p]['head'].update(sha='wrong'),lambda d:d[p]['base'].update(sha='wrong'),lambda d:d[p]['head']['repo'].update(id=0),lambda d:d['branches/main'].update(protected=False),lambda d:d[c]['parents'].append({'sha':'other'}),lambda d:d[t].update(truncated=True),lambda d:d[t]['tree'][0].update(sha='bad'),lambda d:d[r].update(total_count=100),lambda d:d[r]['workflow_runs'].pop(),lambda d:(d[r]['workflow_runs'].append(copy.deepcopy(d[r]['workflow_runs'][0])),d[r].update(total_count=13)),lambda d:d[w].update(path='wrong'),lambda d:d[w].update(run_attempt=2),lambda d:d[w].update(conclusion='failure'),lambda d:d[w].update(pull_requests=[]),lambda d:d[j]['jobs'][0].update(conclusion='skipped'),lambda d:d[j]['jobs'][0].update(name='wrong'),lambda d:d[k]['check_runs'][0]['app'].update(id=0),lambda d:d[k]['check_runs'][0]['check_suite'].update(id=0)]
        for n,mut in enumerate(variants):
            with self.subTest(n=n):
                self.data=fixture(m);mut(self.data)
                with self.assertRaises(a.Hold):self.plan()
    def test_candidate_race(self):
        n=0
        def get(p):
            nonlocal n
            if p=='pulls/'+str(self.m['pr']):
                n+=1
                if n==2:self.data[p]['head']['sha']='wrong'
            return self.data[p]
        with self.assertRaises(a.Hold):a.plan(self.m,get)
    def test_live_exact_emission_and_revocation(self):
        x=self.live(); self.assertEqual(x,{'state':'CHECK_EMITTED','candidate':self.m['head'],'check_id':12345,'release_authorized':False,'token_revoked':True}); self.assertEqual(self.posts,[a.payload(self.m,ENV['GITHUB_RUN_ID'])]); self.assertEqual(self.revoked,['synthetic'])
    def test_live_wrong_context_no_auth(self):
        self.env['GITHUB_EVENT_NAME']='pull_request'
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(self.calls,[])
    def test_live_wrong_identity_no_issue(self):
        self.proof['app_id']=0
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(self.calls,['auth']); self.assertEqual(self.posts,[])
    def test_live_excess_permission_revoked(self):
        self.perms['statuses']='write'
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(self.revoked,['synthetic']);self.assertEqual(self.posts,[])
    def test_live_wrong_scope_revoked(self):
        self.scope['total_count']=2
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(self.revoked,['synthetic']);self.assertEqual(self.posts,[])
    def test_live_governance_race_revoked(self):
        self.gov_race=True
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(self.revoked,['synthetic']);self.assertEqual(self.posts,[])
    def test_live_post_timeout_no_retry(self):
        self.post_error=True
        with self.assertRaises(OSError):self.live()
        self.assertEqual(len(self.posts),1);self.assertEqual(self.revoked,['synthetic'])
    def test_live_wrong_reply(self):
        self.reply_wrong=True
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(len(self.posts),1);self.assertEqual(self.revoked,['synthetic'])
    def test_live_missing_readback(self):
        self.readback_missing=True
        with self.assertRaises(a.Hold):self.live()
        self.assertEqual(len(self.posts),1);self.assertEqual(self.revoked,['synthetic'])
    def test_live_revocation_uncertain(self):
        self.revoke_error=True
        with self.assertRaisesRegex(a.Hold,'CHECK_EMITTED; WRITE_TOKEN_REVOCATION_UNATTESTED'):self.live()
        self.assertEqual(len(self.posts),1)
    def test_live_issuance_uncertain_no_retry(self):
        self.issue_error=True
        with self.assertRaisesRegex(a.Hold,'WRITE_TOKEN_ISSUANCE_UNCERTAIN'):self.live()
        self.assertEqual(self.calls,['auth','issue']);self.assertEqual(self.posts,[])
    def test_bound_transport(self):
        class T:
            def _request(self,method,path,body):return method,path,body
        t=a.bound_transport(T,self.m,'1234')(); body=a.payload(self.m,'1234')
        self.assertEqual(t.post(body),('POST','/repos/'+a.old.REPO+'/check-runs',body))
        for k in body:
            with self.subTest(k=k),self.assertRaises(a.Hold):t.post(dict(body,**{k:'wrong'}))

if __name__=='__main__':unittest.main(verbosity=2)
