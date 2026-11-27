#!/usr/bin/env python3
"""Read-only, fail-closed admission evidence check for the frozen PR #416.
Run from an independent trusted directory; never execute candidate contents.
"""
import json
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import URLError
from urllib.parse import urlsplit

REPO='antoniocorsano-boop/registro-docente'
RID=1428043626
HEAD='1b83f6364985b89cdbd89b73e6c382bd6300f655'
BASE='1e9bcd0eb8bd5c7e72ea059b3f90f72805f9cdd1'
PARENT='b142cc03a8d6b90ee93ec93045e7455ce34639d8'
TREE='ccf173d4cdfedf44533b1d1d7db7bff70b034418'
BRANCH='candidate/cand-prod-01'
APP=15368
ENTRIES={
'.github/workflows/behavior-integrity-qualification.yml':'d0205c714ef623348cf398c411f81d0f5c387461',
'.github/workflows/mobile-density-02-qualification.yml':'8443ac7dcd15e2703812051cfe34bcbcf4e74ce6',
'.github/workflows/nav-context-01-isolated-qualification.yml':'eb366d463f3ab62bf1ad81c80820ab6680d5e1a0',
'scripts/diagnostics/android-r3-admission.sh':'922e4321f154ec76a52153d7a1d9d7c9e5716fc2'}
RUNS={
45937846094:(391941854,['predeploy-security-verify']),
45937846134:(408579107,['qualify-header-01']),
45937846327:(416379230,['behavior-integrity-synthetic-chromium']),
45937846169:(416154802,['mobile-density-02-synthetic-chromium']),
45937846185:(414966856,['android-probe']),
45937846137:(422912819,['preflight','native-evidence (32, v9)','native-evidence (32, legacy)','native-evidence (36, v9)','native-evidence (36, legacy)']),
45937846110:(418894829,['Synthetic Chromium Android 390 / 320','Typecheck / security / invariant contracts']),
45937846129:(394446897,['browser-qualification']),
45937846157:(427396129,['installed-professional-v7 (32)','installed-professional-v7 (36)','R4a startup-only API 32','hybrid-evidence / preflight','hybrid-evidence / pilot (32, 1)','hybrid-evidence / pilot (36, 1)']),
45937846091:(404859404,['flow03-contracts']),
45937846317:(419358552,['compatibility (rc2, 37c61d4c64993c986a3edcd2b421310adf20de92)','compatibility (rc3, b726f4a6dc0eb90a066113bee7cceabf29c629a5)']),
45937846431:(401768724,['qualify-invariants'])}
class Denied(Exception): pass
def require(ok, label):
    if not ok: raise Denied(label)
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

def get(path):
    req=Request('https://api.github.com/repos/'+REPO+'/'+path,headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Registro-Docente-Governance-ReadOnly'})
    with build_opener(NoRedirect()).open(req, timeout=20) as f:
        require(urlsplit(f.geturl()).hostname=='api.github.com','unexpected endpoint')
        data=f.read(20_000_001)
        require(len(data)<=20_000_000,'response too large')
        return json.loads(data)

def check_pr(p):
    require(p['number']==416 and p['state']=='open' and p['merged'] is False,'PR identity/state')
    for key,ref,sha in [('head',BRANCH,HEAD),('base','main',BASE)]:
        v=p[key]; require(v['repo']['id']==RID and v['repo']['full_name']==REPO and v['ref']==ref and v['sha']==sha,'PR '+key)

def verify(fetch=get):
    check_pr(fetch('pulls/416'))
    b=fetch('branches/main'); require(b['name']=='main' and b['commit']['sha']==BASE and b['protected'] is True,'main identity/protection')
    c=fetch('git/commits/'+HEAD)
    require(c['sha']==HEAD and [x['sha'] for x in c['parents']]==[PARENT] and c['tree']['sha']==TREE,'commit parent/tree')
    t=fetch('git/trees/'+TREE+'?recursive=1'); require(t['sha']==TREE and t['truncated'] is False,'complete tree')
    for path,sha in ENTRIES.items():
        rows=[x for x in t['tree'] if x['path']==path]
        require(len(rows)==1 and (rows[0]['sha'],rows[0]['mode'],rows[0]['type'])==(sha,'100644','blob'),'tree entry '+path)
    checks=fetch('commits/'+HEAD+'/check-runs?per_page=100&filter=latest'); require(checks['total_count']==len(checks['check_runs']) and len(checks['check_runs'])<100,'incomplete checks')
    ids=set(); count=0
    for run,(workflow,names) in RUNS.items():
        w=fetch('actions/runs/'+str(run))
        require((w['id'],w['workflow_id'],w['head_sha'],w['head_branch'],w['event'],w['run_attempt'],w['status'],w['conclusion'],w['repository']['id'],w['head_repository']['id'])==(run,workflow,HEAD,BRANCH,'pull_request',1,'completed','success',RID,RID),'workflow '+str(run))
        matches=[p for p in w['pull_requests'] if p['number']==416 and p['head']['sha']==HEAD and p['head']['ref']==BRANCH and p['head']['repo']['id']==RID and p['base']['sha']==BASE and p['base']['ref']=='main' and p['base']['repo']['id']==RID]
        require(len(matches)==1,'workflow PR '+str(run))
        j=fetch('actions/runs/'+str(run)+'/jobs?per_page=100')
        require(j['total_count']==len(j['jobs'])==len(names) and sorted(x['name'] for x in j['jobs'])==sorted(names),'job matrix '+str(run))
        for job in j['jobs']:
            require(job['id'] not in ids and (job['run_id'],job['head_sha'],job['status'],job['conclusion'])==(run,HEAD,'completed','success'),'job evidence '+job['name'])
            same=[x for x in checks['check_runs'] if x['name']==job['name'] and x['app']['id']==APP]
            require(len(same)==1,'ambiguous check '+job['name']); ch=same[0]
            require((ch['id'],ch['head_sha'],ch['status'],ch['conclusion'],ch['check_suite']['id'])==(job['id'],HEAD,'completed','success',w['check_suite_id']),'check provenance '+job['name'])
            ids.add(job['id']); count+=1
    require(count==23,'job total')
    check_pr(fetch('pulls/416'))
    b=fetch('branches/main'); require(b['commit']['sha']==BASE and b['protected'] is True,'final base')
    return {'state':'READ_ONLY_EVIDENCE_PASS','candidate':HEAD,'workflows':len(RUNS),'jobs':count,'published':False,'release_authorized':False}

if __name__=='__main__':
    try: print(json.dumps(verify(),indent=2))
    except (Denied,URLError,OSError,ValueError,TypeError,KeyError,IndexError) as e:
        print('HOLD: '+(str(e) if isinstance(e,Denied) else type(e).__name__))
        raise SystemExit(1)
