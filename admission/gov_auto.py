"""GOV-AUTO-01: automatic admission from an approved protected-main manifest.
No candidate checkout, execution, merge, or release. Policy changes require review.
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.request import Request, build_opener
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'qualified'))
import verify_remote as old

GOV = 'antoniocorsano-boop/registro-docente-governance'
APP = 5948191
INSTALLATION = 186423539
OWNER = '233439245'
CHECK = 'gov-admission-independent'
OUTPUT = {'title':'Independent exact-candidate evidence verified','summary':'12 workflows, 23 jobs; evidence only. Not a merge or release authorization.'}
POLICY = 'RD-12-23-V1'
WORKFLOW = '.github/workflows/gov-auto.yml'
PATHS = {
    391941854: ('predeploy-security-qualification.yml', 'a46b6a9a4a0c846312ae794b1c246dd4d4eaa76f'),
    408579107: ('header-01-isolated-qualification.yml', '63a702f1cb45888efb8f7c33a44cb100344bc51c'),
    416379230: ('behavior-integrity-qualification.yml', 'd0205c714ef623348cf398c411f81d0f5c387461'),
    416154802: ('mobile-density-02-qualification.yml', '8443ac7dcd15e2703812051cfe34bcbcf4e74ce6'),
    414966856: ('mobile-01-android-probe.yml', '3a8cce78e3d812d8d77121a19f0f82e747817fee'),
    422912819: ('val01-native-evidence.yml', 'dd7cf0646cc0cc50f31b857b39ebf3eeeba98650'),
    418894829: ('beta2-reference-qualification.yml', 'f0f710669a3c1ebc5ce3b1d6632cdf707d0dd5d7'),
    394446897: ('browser-qualification.yml', '76a416dce21a7575fa4afcd6b95baa2e1b9333f2'),
    427396129: ('ap02-f2-native-device.yml', 'c66a6983aca608751f8bd5b7ac53f80522beb0c6'),
    404859404: ('flow-03-contract-qualification.yml', 'c7d899776f00cab27dedcd95cbd1247bf1cb04d9'),
    419358552: ('beta2-archive-compatibility.yml', 'e4b8b92adb988c715950f0d0417f4b93fac18d71'),
    401768724: ('qualification-invariants.yml', 'e95265520a314b44b2b43bf3e9fe7fd0a9caf90e'),
}
JOBS = {wid: tuple(names) for wid, names in old.RUNS.values()}
ENTRIES = dict(old.ENTRIES)
ENTRIES.update({'.github/workflows/' + path: blob for path, blob in PATHS.values()})

# Proposed exact build-policy successor; V1 and its historical attestation remain unchanged.
V2_POLICY = 'RD-12-23-V2-R1-BUILD-01A'
V2_MANIFEST = {'schema': 1,
 'policy': 'RD-12-23-V2-R1-BUILD-01A',
 'pr': 416,
 'head': '2e53609d1e627d008e745f043b4e8909b8ed02c3',
 'base': '1e9bcd0eb8bd5c7e72ea059b3f90f72805f9cdd1',
 'parent': 'c05702fdbd85f3c8bc89dfedfb43df8aee3a85ec',
 'tree': '9c1b8205d68ca26fd1b5a3f86dc2b2e8c2c11d71',
 'branch': 'candidate/cand-prod-01'}
V2_DELTA = {'.github/workflows/ap02-f2-native-device.yml': '5378b84cf48d537dff105c181a037dc7f0293590',
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

class Hold(Exception): pass

def need(ok, label):
    if not ok: raise Hold(label)

def sha(s): return isinstance(s, str) and re.fullmatch(r'[0-9a-f]{40}', s) is not None

def number(n): return type(n) is int and 0 < n < 10**20

def context(env):
    fields = {'GITHUB_REPOSITORY': GOV, 'GITHUB_REF': 'refs/heads/main',
              'GITHUB_REF_PROTECTED': 'true', 'GITHUB_EVENT_NAME': 'push',
              'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTOR_ID': OWNER,
              'GITHUB_TRIGGERING_ACTOR': 'antoniocorsano-boop',
              'GITHUB_WORKFLOW_REF': GOV + '/' + WORKFLOW + '@refs/heads/main'}
    for k, v in fields.items(): need(env.get(k) == v, 'context ' + k)
    head = env.get('GITHUB_SHA')
    need(sha(head) and head == env.get('GITHUB_WORKFLOW_SHA'), 'workflow SHA')
    run = env.get('GITHUB_RUN_ID', '')
    need(isinstance(run, str) and re.fullmatch(r'[1-9][0-9]{0,19}', run) is not None, 'run identity')
    return run

def manifest(m):
    need(type(m) is dict and set(m) == {'schema','policy','pr','head','base','parent','tree','branch'}, 'manifest fields')
    need(type(m['schema']) is int and m['schema'] == 1 and m['policy'] in (POLICY, V2_POLICY) and number(m['pr']), 'manifest policy/PR')
    need(all(sha(m[k]) for k in ('head','base','parent','tree')) and m['head'] != m['base'], 'manifest SHA')
    need(isinstance(m['branch'], str) and re.fullmatch(r'candidate/[A-Za-z0-9][A-Za-z0-9_-]{0,79}', m['branch']) is not None, 'candidate branch')
    need(set(PATHS) == set(JOBS) and len(JOBS) == 12 and sum(map(len, JOBS.values())) == 23 and len(ENTRIES) == 14, 'fixed policy')
    if m['policy'] == V2_POLICY:
        need(m == V2_MANIFEST, 'exact V2 manifest')
    else:
        need(m['head'] != V2_MANIFEST['head'], 'V2 candidate requires V2 policy')
    return m.copy()

def policy_entries(m):
    m = manifest(m)
    pins = dict(ENTRIES)
    if m['policy'] == V2_POLICY:
        pins.update(V2_DELTA)
        need(len(pins) == 28 and len(V2_DELTA) == 18 and V2_EXECUTABLE in pins, 'fixed V2 policy')
    return {path:(digest,'100755' if m['policy'] == V2_POLICY and path == V2_EXECUTABLE else '100644','blob')
            for path,digest in pins.items()}

def complete(data, key):
    rows = data[key]
    need(isinstance(rows,list) and data['total_count'] == len(rows) and len(rows) < 100, 'incomplete API page')
    return rows

def check_pr(m, p):
    need(p['number'] == m['pr'] and p['state'] == 'open' and p['merged'] is False, 'PR identity/state')
    for key, ref, digest in [('head',m['branch'],m['head']),('base','main',m['base'])]:
        q = p[key]
        need((q['repo']['id'],q['repo']['full_name'],q['ref'],q['sha']) == (old.RID,old.REPO,ref,digest), 'PR ' + key)

def check_base(m, fetch):
    b = fetch('branches/main')
    need(b['name'] == 'main' and b['commit']['sha'] == m['base'] and b['protected'] is True, 'main identity/protection')

def final_candidate(m, fetch):
    check_pr(m, fetch('pulls/' + str(m['pr'])))
    check_base(m, fetch)

def attestation(m, fetch):
    rows = complete(fetch('commits/' + m['head'] + '/check-runs?per_page=100&filter=all'), 'check_runs')
    same = [x for x in rows if x['name'] == CHECK]
    if not same: return None
    need(len(same) == 1, 'duplicate attestation')
    c = same[0]
    need((c['app']['id'],c['head_sha'],c['status'],c['conclusion']) == (APP,m['head'],'completed','success') and number(c['id']), 'conflicting attestation')
    pattern = r'GOV-AUTO-01:' + re.escape(m['policy']) + ':' + m['head'] + r':([1-9][0-9]{0,19})'
    match = re.fullmatch(pattern, c['external_id'] or '')
    # Only the already-qualified historical check is grandfathered into this policy.
    if match is None:
        need(m['policy'] == POLICY and m['head'] == old.HEAD and c['id'] == 140661146635 and c['external_id'] == 'GOV-ADMISSION-04:'+old.HEAD+':46044433279', 'historical attestation binding')
        source_run = '46044433279'
    else: source_run = match[1]
    need(c['details_url'] == 'https://github.com/' + GOV + '/actions/runs/' + source_run, 'attestation provenance')
    need(all(c['output'].get(k) == v for k,v in OUTPUT.items()), 'attestation evidence')
    return c['id']

def plan(m, fetch):
    m = manifest(m)
    final_candidate(m, fetch)
    c = fetch('git/commits/' + m['head'])
    need(c['sha'] == m['head'] and [x['sha'] for x in c['parents']] == [m['parent']] and c['tree']['sha'] == m['tree'], 'commit parent/tree')
    t = fetch('git/trees/' + m['tree'] + '?recursive=1')
    need(t['sha'] == m['tree'] and t['truncated'] is False, 'complete tree')
    for path, expected in policy_entries(m).items():
        rows = [x for x in t['tree'] if x['path'] == path]
        need(len(rows) == 1 and (rows[0]['sha'],rows[0]['mode'],rows[0]['type']) == expected, 'policy blob drift')
    runs = complete(fetch('actions/runs?head_sha=' + m['head'] + '&event=pull_request&per_page=100'), 'workflow_runs')
    checks = complete(fetch('commits/' + m['head'] + '/check-runs?per_page=100&filter=latest'), 'check_runs')
    ids = set(); run_ids = set()
    for wid, names in JOBS.items():
        matches = [w for w in runs if w['workflow_id'] == wid]
        need(len(matches) == 1 and number(matches[0]['id']), 'missing/ambiguous workflow')
        rid = matches[0]['id']
        need(rid not in run_ids, 'duplicate run'); run_ids.add(rid)
        w = fetch('actions/runs/' + str(rid))
        need((w['id'],w['workflow_id'],w['path'],w['head_sha'],w['head_branch'],w['event'],w['run_attempt'],w['status'],w['conclusion'],w['repository']['id'],w['head_repository']['id']) == (rid,wid,'.github/workflows/'+PATHS[wid][0],m['head'],m['branch'],'pull_request',1,'completed','success',old.RID,old.RID), 'workflow provenance')
        related = [p for p in w['pull_requests'] if p['number'] == m['pr'] and p['head']['sha'] == m['head'] and p['head']['ref'] == m['branch'] and p['head']['repo']['id'] == old.RID and p['base']['sha'] == m['base'] and p['base']['ref'] == 'main' and p['base']['repo']['id'] == old.RID]
        need(len(related) == 1, 'workflow PR binding')
        jobs = complete(fetch('actions/runs/' + str(rid) + '/jobs?per_page=100'), 'jobs')
        need(sorted(x['name'] for x in jobs) == sorted(names), 'job matrix')
        for j in jobs:
            need(number(j['id']) and j['id'] not in ids and (j['run_id'],j['head_sha'],j['status'],j['conclusion']) == (rid,m['head'],'completed','success'), 'job evidence')
            same = [x for x in checks if x['name'] == j['name'] and x['app']['id'] == old.APP]
            need(len(same) == 1, 'ambiguous job check')
            ch = same[0]
            need((ch['id'],ch['head_sha'],ch['status'],ch['conclusion'],ch['check_suite']['id']) == (j['id'],m['head'],'completed','success',w['check_suite_id']), 'check provenance')
            ids.add(j['id'])
    need(len(ids) == 23 and len(run_ids) == 12, 'evidence totals')
    final_candidate(m, fetch)
    existing = attestation(m, fetch)
    return {'decision':'already' if existing is not None else 'ready','candidate':m['head'],'workflows':12,'jobs':23,'check_id':existing,'release_authorized':False}

class ReadHTTP(Hold):
    """Fixed labels and bounded numeric headers only; never log URLs or bodies."""
    def __init__(self, phase, exc):
        def numeric(name):
            value = exc.headers.get(name, '') if exc.headers else ''
            return value if re.fullmatch(r'[0-9]{1,12}', value) else 'unknown'
        self.status = exc.code
        self.phase = phase
        self.remaining = numeric('X-RateLimit-Remaining')
        super().__init__(f'{phase} HTTP {self.status}; remaining={self.remaining}; retry_after={numeric("Retry-After")}')


def read_json(repo, path, phase, token=None, opener=None):
    need(repo in (GOV,old.REPO), 'read repository')
    if repo == GOV:
        need(path == 'branches/main' and phase == 'governance', 'governance read route')
    else:
        need(phase == 'candidate' and re.fullmatch(r'(?:pulls/[1-9][0-9]{0,19}|branches/main|git/commits/[0-9a-f]{40}|git/trees/[0-9a-f]{40}\?recursive=1|actions/runs\?head_sha=[0-9a-f]{40}&event=pull_request&per_page=100|actions/runs/[1-9][0-9]{0,19}(?:/jobs\?per_page=100)?|commits/[0-9a-f]{40}/check-runs\?per_page=100&filter=(?:latest|all))',path), 'candidate read route')
    url = 'https://api.github.com/repos/' + repo + '/' + path
    headers = {'Accept':'application/vnd.github+json','User-Agent':'Registro-Docente-GOV-AUTO-01','X-GitHub-Api-Version':'2022-11-28'}
    if token is not None:
        need(isinstance(token,str) and token and not any(c.isspace() for c in token), 'read credential')
        headers['Authorization'] = 'Bearer ' + token
    try:
        with (opener or build_opener(old.NoRedirect())).open(Request(url,headers=headers,method='GET'),timeout=20) as f:
            need(f.geturl() == url and f.status == 200, 'read endpoint/status')
            raw = f.read(20_000_001); need(len(raw) <= 20_000_000, 'read response size')
            return json.loads(raw)
    except HTTPError as exc:
        # Do not log arbitrary paths, header text, or response bodies.
        label = phase if repo == GOV else 'candidate/' + path.split('/')[0].split('?')[0]
        raise ReadHTTP(label,exc) from None


def current_governance(env):
    b = read_json(GOV,'branches/main','governance',env.get('GOV_READ_TOKEN',''))
    need(b['name'] == 'main' and b['protected'] is True and b['commit']['sha'] == env['GITHUB_SHA'], 'governance main changed')


def public_plan(m, fetch):
    try: return plan(m,fetch)
    except ReadHTTP as exc:
        # Switch only to the existing, separately approved authenticated route.
        # No retry of the public request, and no fallback on evidence mismatch.
        if exc.status not in (401,403,429): raise
        return {'decision':'protected_read','candidate':m['head'],'diagnostic':str(exc),'release_authorized':False}


def protected_plan(m, credential, probe, request, fetch_factory):
    """Reuse the qualified read-only identity/scope probe and its finally-revoke."""
    result = None
    def observed(method,path,token,body=None):
        nonlocal result
        data = request(method,path,token,body)
        if method == 'GET' and path == '/installation/repositories?per_page=100':
            need(result is None, 'duplicate read scope')
            need(data['total_count'] == len(data['repositories']) == 1 and (data['repositories'][0]['id'],data['repositories'][0]['full_name']) == (old.RID,old.REPO), 'read token scope')
            result = plan(m,fetch_factory(token))
        return data
    proof = probe(credential,observed)
    need(proof == {'state':'AUTH_SCOPE_PASS','app_id':APP,'installation_id':INSTALLATION,'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}, 'protected read proof')
    need(result is not None, 'protected read result missing')
    return dict(result,token_revoked=True)


def payload(m, run):
    m = manifest(m)
    return {'name':CHECK,'head_sha':m['head'],'status':'completed','conclusion':'success',
            'external_id':'GOV-AUTO-01:'+m['policy']+':'+m['head']+':'+run,
            'details_url':'https://github.com/'+GOV+'/actions/runs/'+run,
            'output':OUTPUT.copy()}

def bound_transport(base, m, run):
    expected = payload(manifest(m),run)
    class BoundTransport(base):
        def post(self, body):
            need(body == expected, 'exact payload')
            return self._request('POST','/repos/'+old.REPO+'/check-runs',body)
    return BoundTransport

def execute_live(env, m, credential, auth, issue, factory, revoke, governance, permissions):
    run = context(env); m = manifest(m); governance(env)
    proof = auth(credential)
    need(proof == {'state':'AUTH_SCOPE_PASS','app_id':APP,'installation_id':INSTALLATION,'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}, 'authentication proof')
    try: response = issue(credential)
    except Exception: raise Hold('WRITE_TOKEN_ISSUANCE_UNCERTAIN; no retry') from None
    token = response.get('token') if isinstance(response,dict) else None
    need(isinstance(token,str) and token and not any(c.isspace() for c in token), 'WRITE_TOKEN_UNAVAILABLE; reconcile issuance')
    state = 'NO_CHECK_ATTEMPT'
    try:
        need(response.get('permissions') == permissions, 'write token permissions')
        t = factory(token)
        scope = t.scope()
        need(scope['total_count'] == len(scope['repositories']) == 1 and (scope['repositories'][0]['id'],scope['repositories'][0]['full_name']) == (old.RID,old.REPO), 'write token scope')
        result = plan(m, t.fetch)
        if result['decision'] == 'already':
            state = 'ALREADY_ATTESTED'; result = dict(result, state=state)
        else:
            need(attestation(m,t.fetch) is None, 'attestation changed; reconcile')
            final_candidate(m,t.fetch); governance(env)
            body = payload(m,run); state = 'CHECK_ATTEMPT_UNCERTAIN'
            reply = t.post(body)
            need((reply['name'],reply['head_sha'],reply['status'],reply['conclusion'],reply['app']['id'],reply['external_id'],reply['details_url']) == (CHECK,m['head'],'completed','success',APP,body['external_id'],body['details_url']) and number(reply['id']), 'post response identity')
            state = 'CHECK_EMITTED'
            need(attestation(m,t.fetch) == reply['id'], 'published attestation readback')
            result = {'state':state,'candidate':m['head'],'check_id':reply['id'],'release_authorized':False}
    finally:
        try: revoke(token)
        except Exception: raise Hold(state+'; WRITE_TOKEN_REVOCATION_UNATTESTED; reconcile, no retry') from None
    return dict(result, token_revoked=True)

def load_manifest():
    def unique(pairs):
        out = {}
        for k,v in pairs:
            need(k not in out, 'duplicate manifest key'); out[k] = v
        return out
    p = ROOT/'candidate.json'
    need(p.is_file() and not p.is_symlink() and p.stat().st_size <= 4096, 'manifest file')
    return manifest(json.loads(p.read_text(encoding='utf-8'),object_pairs_hook=unique))

def main():
    try:
        run = context(os.environ); m = load_manifest(); current_governance(os.environ)
        need(len(sys.argv)==2 and sys.argv[1] in ('plan','live'), 'mode')
        if sys.argv[1] == 'plan':
            result = public_plan(m,lambda path:read_json(old.REPO,path,'candidate'))
            with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f: f.write('decision='+result['decision']+'\n')
        else:
            # Imported only in the environment-protected live job.
            import auth_probe as a
            import integration as i
            import emitter as e
            BoundTransport = bound_transport(e.InstallationTransport,m,run)
            key = os.environ.pop('GOV_APP_PRIVATE_KEY',''); credential = a.jwt(key); del key
            req = a.Transport().request
            decision = os.environ.get('GOV_PLAN_DECISION')
            need(decision in ('ready','protected_read'), 'approved decision')
            result = protected_plan(m,credential,a.probe,req,lambda token:lambda path:read_json(old.REPO,path,'candidate',token)) if decision == 'protected_read' else None
            if result is not None and result['decision'] == 'already':
                result = dict(result,state='ALREADY_ATTESTED')
            else:
                result = execute_live(os.environ,m,credential,lambda c:a.probe(c,req),i.issue,BoundTransport,lambda token:req('DELETE','/installation/token',token),current_governance,i.WRITE_PERMS)
        print(json.dumps(result,sort_keys=True))
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a',encoding='utf-8') as f:
            f.write('```json\n'+json.dumps(result,sort_keys=True,indent=2)+'\n```\n')
    except Exception as exc:
        print('HOLD: '+(str(exc) if isinstance(exc,Hold) else type(exc).__name__)+'; inspect evidence before retry')
        raise SystemExit(1)

if __name__ == '__main__': main()
