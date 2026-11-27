"""GOV-ADMISSION-04: attestation emitter core; no live entrypoint.
No candidate code is loaded. Authentication and real activation are a separate gate.
"""
import json
import re
from urllib.request import Request, build_opener
from urllib.parse import urlsplit
from verify_remote import verify, check_pr, require, Denied, NoRedirect, REPO, RID, HEAD, BASE

APP_ID = 5948191
GOV = 'antoniocorsano-boop/registro-docente-governance'
CHECK = 'gov-admission-independent'
EMIT_WORKFLOW = '.github/workflows/gov-admission-emit.yml'
EXPECTED = {'state':'READ_ONLY_EVIDENCE_PASS','candidate':HEAD,'workflows':12,'jobs':23,'published':False,'release_authorized':False}


def context_guard(env):
    expected = {'GITHUB_REPOSITORY':GOV,'GITHUB_REF':'refs/heads/main',
                'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1',
                'GITHUB_WORKFLOW_REF':GOV+'/'+EMIT_WORKFLOW+'@refs/heads/main',
                'GOV_ADMISSION_MODE':'live'}
    for key,value in expected.items():
        require(env.get(key)==value,'context '+key)
    run = env.get('GITHUB_RUN_ID','')
    require(isinstance(run,str) and re.fullmatch(r'[1-9][0-9]{0,19}',run) is not None,'run identity')
    return run


def check_scope(data):
    require(data['total_count']==1 and len(data['repositories'])==1,'installation scope')
    repo=data['repositories'][0]
    require((repo['id'],repo['full_name'])==(RID,REPO),'installation repository')


def emit(env, fetch, scope, identity, post):
    """Called only by a future, independently reviewed privileged workflow.
    No retry on POST error: ambiguous result requires read-only reconciliation.
    """
    run=context_guard(env)
    require(identity()==APP_ID,'verified App identity')
    check_scope(scope())
    result=verify(fetch)
    require(result==EXPECTED,'exact evidence result')
    checks=fetch('commits/'+HEAD+'/check-runs?per_page=100&filter=latest')
    require(checks['total_count']==len(checks['check_runs']) and len(checks['check_runs'])<100,'incomplete checks')
    same=[x for x in checks['check_runs'] if x['name']==CHECK]
    require(not same,'existing or conflicting attestation: reconcile, do not duplicate')
    check_pr(fetch('pulls/416'))
    b=fetch('branches/main')
    require(b['name']=='main' and b['commit']['sha']==BASE and b['protected'] is True,'final base')
    payload={'name':CHECK,'head_sha':HEAD,'status':'completed','conclusion':'success',
             'external_id':'GOV-ADMISSION-04:'+HEAD+':'+run,
             'details_url':'https://github.com/'+GOV+'/actions/runs/'+run,
             'output':{'title':'Independent exact-candidate evidence verified',
                       'summary':'12 workflows, 23 jobs; evidence only. Not a merge or release authorization.'}}
    reply=post(payload)
    require((reply['name'],reply['head_sha'],reply['status'],reply['conclusion'],reply['app']['id'],reply['external_id'])==
            (CHECK,HEAD,'completed','success',APP_ID,payload['external_id']),'post response identity')
    require(type(reply['id']) is int and reply['id']>0,'check identity')
    return {'state':'CHECK_EMITTED','check_id':reply['id'],'candidate':HEAD,'release_authorized':False}


class InstallationTransport:
    """Prepared transport. Not used by qualification YAML. Token is ephemeral.
    Future activation must obtain it from the pinned App and verify installation permissions.
    """
    def __init__(self, token, opener=None):
        require(isinstance(token,str) and token and not any(c.isspace() for c in token),'invalid token')
        self._token=token
        self._opener=opener or build_opener(NoRedirect())

    def _request(self, method, path, body=None):
        # Only the fixed repository and scope endpoint; no caller-controlled origin.
        valid_get=(path=='/installation/repositories?per_page=100' or
                   path.startswith('/repos/'+REPO+'/'))
        valid_post=path=='/repos/'+REPO+'/check-runs'
        require((method=='GET' and body is None and valid_get) or (method=='POST' and valid_post and isinstance(body,dict)), 'transport route')
        require('..' not in path and '#' not in path and '%' not in path and '\\' not in path, 'transport path')
        url='https://api.github.com'+path
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',
                 'User-Agent':'Registro-Docente-Governance','Authorization':'Bearer '+self._token}
        if body is not None: headers['Content-Type']='application/json'
        req=Request(url, data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
        with self._opener.open(req,timeout=20) as f:
            require(urlsplit(f.geturl()).hostname=='api.github.com' and f.geturl()==url,'unexpected endpoint')
            require(f.status==(201 if method=='POST' else 200),'unexpected HTTP status')
            raw=f.read(20_000_001)
            require(len(raw)<=20_000_000,'response too large')
            return json.loads(raw)

    def fetch(self,path): return self._request('GET','/repos/'+REPO+'/'+path)
    def scope(self): return self._request('GET','/installation/repositories?per_page=100')
    def post(self,payload):
        require(isinstance(payload,dict) and set(payload)=={'name','head_sha','status','conclusion','external_id','details_url','output'},'payload fields')
        require((payload['name'],payload['head_sha'],payload['status'],payload['conclusion'])==(CHECK,HEAD,'completed','success'),'payload identity')
        require(re.fullmatch(r'GOV-ADMISSION-04:'+HEAD+r':[1-9][0-9]{0,19}',payload['external_id']) is not None,'payload external ID')
        require(payload['details_url']=='https://github.com/'+GOV+'/actions/runs/'+payload['external_id'].rsplit(':',1)[1],'payload details URL')
        require(payload['output']=={'title':'Independent exact-candidate evidence verified','summary':'12 workflows, 23 jobs; evidence only. Not a merge or release authorization.'},'payload output')
        return self._request('POST','/repos/'+REPO+'/check-runs',payload)

if __name__=='__main__':
    raise SystemExit('HOLD: live entrypoint not enabled; qualification only')
