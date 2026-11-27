"""GOV-ADMISSION-07: glue only. No application or release operation."""
import json, os, re
from urllib.request import Request, build_opener
import auth_probe as a
import emitter as e
import verify_remote as v

INSTALLATION = 186423539
WRITE_PERMS = {'actions':'read','checks':'write','contents':'read','metadata':'read','pull_requests':'read'}

class Hold(Exception): pass

def require(ok, label):
    if not ok: raise Hold(label)

def guard(env):
    e.context_guard(env)
    require(env.get('GITHUB_ACTOR_ID') == str(a.OWNER[1]), 'owner')
    require(env.get('GITHUB_TRIGGERING_ACTOR') == a.OWNER[0], 'triggering owner')
    require(env.get('GITHUB_REF_PROTECTED') == 'true', 'protected ref')
    sha = env.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}',sha) is not None and env.get('GITHUB_WORKFLOW_SHA') == sha, 'workflow SHA')

def issue(credential, opener=None):
    require(isinstance(credential,str) and credential and not any(c.isspace() for c in credential),'credential')
    url = f'https://api.github.com/app/installations/{INSTALLATION}/access_tokens'
    data = json.dumps({'permissions':WRITE_PERMS,'repository_ids':[a.RID]}).encode()
    req = Request(url, data=data, method='POST', headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Registro-Docente-Governance-07','Authorization':'Bearer '+credential,'Content-Type':'application/json'})
    with (opener or build_opener(a.NoRedirect())).open(req, timeout=20) as f:
        require(f.geturl()==url and f.status==201,'token response endpoint/status')
        raw = f.read(4_000_001)
        require(len(raw)<=4_000_000,'token response size')
        return json.loads(raw)

def run(env, credential, auth_request, issue_token, transport_factory):
    guard(env)
    proof = a.probe(credential, auth_request)
    require(proof == {'state':'AUTH_SCOPE_PASS','app_id':a.APP,'installation_id':INSTALLATION,'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}, 'authentication proof')
    # Exactly one issuance. A lost response must be reconciled, not retried.
    try:
        response = issue_token(credential)
    except Exception:
        raise Hold('WRITE_TOKEN_ISSUANCE_UNCERTAIN; no retry') from None
    token = response.get('token') if isinstance(response,dict) else None
    require(isinstance(token,str) and token and not any(c.isspace() for c in token), 'WRITE_TOKEN_UNAVAILABLE; reconcile issuance')
    state = 'NO_CHECK_ATTEMPT'
    try:
        require(response.get('permissions') == WRITE_PERMS, 'write token permissions')
        t = transport_factory(token)
        def post(payload):
            nonlocal state
            state = 'CHECK_ATTEMPT_UNCERTAIN'
            return t.post(payload)
        result = e.emit(env,t.fetch,t.scope,lambda:proof['app_id'],post)
        state = 'CHECK_EMITTED'
    finally:
        try:
            auth_request('DELETE','/installation/token',token)
        except Exception:
            raise Hold(state+'; WRITE_TOKEN_REVOCATION_UNATTESTED; reconcile, no retry') from None
    require(result['state']=='CHECK_EMITTED' and result['release_authorized'] is False,'emission result')
    return dict(result,token_revoked=True)

def main():
    try:
        guard(os.environ)
        key = os.environ.pop('GOV_APP_PRIVATE_KEY','')
        credential = a.jwt(key); del key
        result = run(os.environ,credential,a.Transport().request,issue,e.InstallationTransport)
        print(json.dumps(result,sort_keys=True))
    except Exception as exc:
        # Only fixed local labels; no HTTP body, token, or key output.
        print('HOLD: '+(str(exc) if isinstance(exc,Hold) else type(exc).__name__)+'; inspect evidence in read-only mode before any retry')
        raise SystemExit(1)

if __name__=='__main__': main()
