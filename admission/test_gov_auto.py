import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import gov_auto as a

PERMS={'actions':'read','checks':'write','contents':'read','metadata':'read','pull_requests':'read'}
PROOF={'state':'AUTH_SCOPE_PASS','app_id':a.APP,'installation_id':a.INSTALLATION,'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}
ENV={'GITHUB_REPOSITORY':a.GOV,'GITHUB_REF':'refs/heads/main','GITHUB_REF_PROTECTED':'true','GITHUB_EVENT_NAME':'push','GITHUB_RUN_ATTEMPT':'1','GITHUB_ACTOR_ID':a.OWNER,'GITHUB_TRIGGERING_ACTOR':'antoniocorsano-boop','GITHUB_WORKFLOW_REF':a.GOV+'/'+a.WORKFLOW+'@refs/heads/main','GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,'GITHUB_RUN_ID':'1234'}

def historical_manifest():
    # The migration/equivalence evidence is tied to the qualified #416 fixture,
    # never to the operational candidate.json selected for this workflow run.
    return {'schema':1,'policy':a.POLICY,'pr':416,'head':a.old.HEAD,'base':a.old.BASE,
            'parent':a.old.PARENT,'tree':a.old.TREE,'branch':a.old.BRANCH}

def future_manifest():
    return {'schema':1,'policy':a.POLICY,'pr':500,'head':'b'*40,'base':'c'*40,
            'parent':'d'*40,'tree':'e'*40,'branch':'candidate/next'}

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
        self.m=historical_manifest(); self.env=ENV.copy(); self.data=fixture(self.m); self.calls=[]; self.posts=[]; self.revoked=[]
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
        self.m=future_manifest(); self.data=fixture(self.m); self.assertEqual(self.plan()['candidate'],'b'*40)
    def test_fixture_independence_without_operational_loader(self):
        with patch.object(a,'load_manifest',side_effect=AssertionError('operational manifest must not be used by fixtures')):
            probe=Tests(); probe.setUp()
            probe.test_equivalent_to_qualified_verifier()
            probe.test_existing_attestation_no_second_emission()
            probe.setUp(); probe.test_future_candidate_not_frozen()
    def test_operational_manifest_loader_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); candidate=root/'candidate.json'
            with patch.object(a,'ROOT',root):
                for expected in (historical_manifest(),future_manifest()):
                    candidate.write_text(json.dumps(expected),encoding='utf-8')
                    self.assertEqual(a.load_manifest(),expected)
                    self.assertEqual(historical_manifest()['head'],a.old.HEAD)
                    self.assertEqual(future_manifest()['head'],'b'*40)
                candidate.write_text('{"schema":1,"schema":1}',encoding='utf-8')
                with self.assertRaisesRegex(a.Hold,'duplicate manifest key'):a.load_manifest()
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
        self.m=future_manifest(); self.data=fixture(self.m)
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


# R1-BUILD-01a: exact manifest and expected remote tree entries.
V2_EXPECTED = {'schema': 1,
 'policy': 'RD-12-23-V2-R1-BUILD-01A',
 'pr': 416,
 'head': '2e53609d1e627d008e745f043b4e8909b8ed02c3',
 'base': '1e9bcd0eb8bd5c7e72ea059b3f90f72805f9cdd1',
 'parent': 'c05702fdbd85f3c8bc89dfedfb43df8aee3a85ec',
 'tree': '9c1b8205d68ca26fd1b5a3f86dc2b2e8c2c11d71',
 'branch': 'candidate/cand-prod-01'}
V2_EXPECTED_DELTA = {'.github/workflows/ap02-f2-native-device.yml': '5378b84cf48d537dff105c181a037dc7f0293590',
 '.github/workflows/mobile-01-android-probe.yml': 'f799960ac848a7dc711a83a75a5f11f21aa6576a',
 '.github/workflows/qa-appium-replacement-pilot.yml': 'aea9cc43b1f86530f7eecad921a241597e5c0e23',
 '.github/workflows/val01-native-evidence.yml': '6564f1eae2838d23e2e18502b7fe35a8ceeaf08e',
 'mobile/android-probe/.gitignore': '60ff708259ae686b99baa2bde8625465f2ae74fe',
 'mobile/android-probe/build-contract.py': '834f29d61c4c5b8b3d7ab49ae77de7409087d116',
 'mobile/android-probe/build-inventory.init.gradle': '633ccf85fd94ea2b63f8fe6599e23c31a7e818f3',
 'mobile/android-probe/gradle-8.14.8/.gitattributes': '3cec56724bc7eb7b519330c29c44a369cb8e90be',
 'mobile/android-probe/gradle-8.14.8/gradle-wrapper.jar': '02f06ab2a396743f0052e4328b0e5ac2cdd8b3d2',
 'mobile/android-probe/gradle-8.14.8/gradlew': '23d15a9367071145e9c79bb4ddf879d1fbe78b5d',
 'mobile/android-probe/gradle-8.14.8/gradlew.bat': '5eed7ee8452842305a18a4eb967442683808226a',
 'mobile/android-probe/package-lock.json': 'e6d10b0004fcf98fd5abdb15c3e50fab6efac042',
 'mobile/android-probe/probe-npm.sh': '2cee04e14a14b1375e4a773910bce85988b531fa',
 'mobile/android-probe/test_native_inventory.py': '6ad00aeb84cbdfd91ba39690d3f5eff2f63aa107',
 'mobile/android-probe/verification-metadata.xml': '171aff841a11b8307f5ef1ccdece58a47615cda4',
 'mobile/android-probe/verify-build-inventory.py': '018b89b6ec0c407634858164fbf84a642a861a22',
 'scripts/diagnostics/android-r3-admission.sh': '365666236452a36ba1c54c8eb951835f8c686791',
 'scripts/diagnostics/appium-pilot/contract.test.mjs': 'bf198e13fe028a689769dbfe3ba0cf6dadf12ac5'}
V2_EXECUTABLE = 'mobile/android-probe/gradle-8.14.8/gradlew'

def v2_fixture():
    m = V2_EXPECTED.copy()
    data = fixture(m)
    pins = dict(a.ENTRIES)
    pins.update(V2_EXPECTED_DELTA)
    data['git/trees/'+m['tree']+'?recursive=1']['tree'] = [
        {'path':path,'sha':digest,'mode':'100755' if path == V2_EXECUTABLE else '100644','type':'blob'}
        for path,digest in pins.items()]
    return m, data

class R1Build01aTests(unittest.TestCase):
    def setUp(self):
        self.m, self.data = v2_fixture()

    def plan(self):
        return a.plan(self.m,self.data.__getitem__)

    def tree(self):
        return self.data['git/trees/'+self.m['tree']+'?recursive=1']['tree']

    def check_key(self, f):
        return 'commits/'+self.m['head']+'/check-runs?per_page=100&filter='+f

    def test_exact_v2_plan(self):
        self.assertEqual(len(self.tree()),28)
        self.assertEqual(self.plan(),{'decision':'ready','candidate':self.m['head'],'workflows':12,'jobs':23,'check_id':None,'release_authorized':False})

    def test_v2_manifest_exact(self):
        self.assertEqual(a.manifest(self.m),self.m)
        for field in ('pr','head','base','parent','tree','branch','schema','policy'):
            changed=dict(self.m,**{field:{'pr':417,'schema':2,'branch':'candidate/other','policy':a.POLICY}.get(field,'f'*40)})
            with self.subTest(field=field), self.assertRaises(a.Hold):
                a.manifest(changed)

    def test_v2_pin_missing_wrong_mode_type_duplicate(self):
        for path in [x['path'] for x in self.tree()]:
            for kind in ('missing','digest','mode','type','duplicate'):
                self.m,self.data=v2_fixture(); rows=self.tree(); row=next(x for x in rows if x['path']==path)
                if kind=='missing':rows.remove(row)
                elif kind=='digest':row['sha']='0'*40
                elif kind=='mode':row['mode']='100644' if row['mode']=='100755' else '100755'
                elif kind=='type':row['type']='tree'
                else:rows.append(copy.deepcopy(row))
                with self.subTest(path=path,kind=kind),self.assertRaisesRegex(a.Hold,'policy blob drift'):
                    self.plan()

    def test_v1_not_accepted_for_v2(self):
        self.m['policy']=a.POLICY
        with self.assertRaises(a.Hold):self.plan()

    def test_v2_rejects_v1_tree(self):
        self.tree()[:]=fixture(self.m)['git/trees/'+self.m['tree']+'?recursive=1']['tree']
        with self.assertRaisesRegex(a.Hold,'policy blob drift'):self.plan()

    def test_v2_check_policy_binding(self):
        result=a.payload(self.m,'777')
        self.assertEqual(result['external_id'],'GOV-AUTO-01:'+self.m['policy']+':'+self.m['head']+':777')
        self.assertEqual(result['output'],a.OUTPUT)
        result.update(id=88,app={'id':a.APP})
        for f in ('latest','all'):
            row=self.data[self.check_key(f)];row['check_runs'].append(copy.deepcopy(result));row['total_count']+=1
        self.assertEqual(self.plan()['decision'],'already')
        self.data[self.check_key('all')]['check_runs'][-1]['external_id']=result['external_id'].replace(self.m['policy'],a.POLICY)
        with self.assertRaises(a.Hold):self.plan()

    def test_v2_does_not_inherit_historical_check(self):
        p=a.payload(historical_manifest(),'46044433279'); p.update(external_id='GOV-ADMISSION-04:'+a.old.HEAD+':46044433279',id=140661146635,app={'id':a.APP},head_sha=self.m['head'])
        key=self.check_key('all');self.data[key]['check_runs'].append(p);self.data[key]['total_count']+=1
        with self.assertRaises(a.Hold):self.plan()

    def test_v2_job_and_check_fail_closed(self):
        job_key='actions/runs/45937846094/jobs?per_page=100'
        for kind in ('job_missing','job_skipped','check_missing','check_duplicate','wrong_base','wrong_parent','wrong_tree','unprotected'):
            self.m,self.data=v2_fixture();checks=self.data[self.check_key('latest')]
            if kind=='job_missing':self.data[job_key]['jobs'].clear();self.data[job_key]['total_count']=0
            elif kind=='job_skipped':self.data[job_key]['jobs'][0]['conclusion']='skipped'
            elif kind=='check_missing':checks['check_runs'].pop(0);checks['total_count']-=1
            elif kind=='check_duplicate':checks['check_runs'].append(copy.deepcopy(checks['check_runs'][0]));checks['total_count']+=1
            elif kind=='wrong_base':self.data['branches/main']['commit']['sha']='f'*40
            elif kind=='wrong_parent':self.data['git/commits/'+self.m['head']]['parents'][0]['sha']='f'*40
            elif kind=='wrong_tree':self.data['git/commits/'+self.m['head']]['tree']['sha']='f'*40
            else:self.data['branches/main']['protected']=False
            with self.subTest(kind=kind),self.assertRaises(a.Hold):self.plan()

    def test_v2_live_synthetic_revocation_and_dedup(self):
        probe=Tests();probe.setUp();probe.m=self.m;probe.data=self.data
        out=probe.live()
        self.assertEqual(out['state'],'CHECK_EMITTED');self.assertTrue(out['token_revoked']);self.assertFalse(out['release_authorized'])
        self.assertEqual(probe.posts,[a.payload(self.m,ENV['GITHUB_RUN_ID'])]);self.assertEqual(probe.revoked,['synthetic'])
        out=probe.live();self.assertEqual(out['state'],'ALREADY_ATTESTED');self.assertEqual(len(probe.posts),1);self.assertEqual(probe.revoked,['synthetic','synthetic'])

    def test_v2_live_mutated_tree_never_posts(self):
        probe=Tests();probe.setUp();probe.m=self.m;probe.data=self.data
        self.tree()[0]['sha']='0'*40
        with self.assertRaisesRegex(a.Hold,'policy blob drift'):probe.live()
        self.assertEqual(probe.posts,[]);self.assertEqual(probe.revoked,['synthetic'])

    def test_v2_no_fallback_on_policy_mismatch(self):
        self.tree()[0]['mode']='120000'
        with self.assertRaisesRegex(a.Hold,'policy blob drift'):a.public_plan(self.m,self.data.__getitem__)

    def test_v2_manifest_loader_independent_of_v1(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);candidate=root/'candidate.json'
            candidate.write_text(json.dumps(self.m),encoding='utf-8')
            with patch.object(a,'ROOT',root):
                self.assertEqual(a.load_manifest(),self.m)
                m=historical_manifest();self.assertEqual(a.plan(m,fixture(m).__getitem__)['decision'],'ready')

if __name__=='__main__':unittest.main(verbosity=2)
