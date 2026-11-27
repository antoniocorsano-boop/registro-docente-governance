"""GOV-ADMISSION-05: App identity and installation scope probe. No check publication."""
import base64, json, os, re, subprocess, time
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import URLError

APP=5948191
OWNER=('antoniocorsano-boop',233439245)
REPO='antoniocorsano-boop/registro-docente'
RID=1428043626
GOV='antoniocorsano-boop/registro-docente-governance'
WORKFLOW='.github/workflows/gov-admission-auth-probe.yml'
APP_PERMS={'actions':'read','checks':'write','statuses':'write','contents':'read','metadata':'read','pull_requests':'read'}
READ_PERMS={k:'read' for k in APP_PERMS}
class Hold(Exception): pass
def require(value,label):
    if not value: raise Hold(label)

def guard(env):
    expected={'GITHUB_REPOSITORY':GOV,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_REF':GOV+'/'+WORKFLOW+'@refs/heads/main','GITHUB_ACTOR_ID':str(OWNER[1]),'GITHUB_TRIGGERING_ACTOR':OWNER[0],'GOV_ADMISSION_MODE':'authenticate'}
    for key,value in expected.items(): require(env.get(key)==value,'context '+key)
    require(re.fullmatch(r'[1-9][0-9]{0,19}',env.get('GITHUB_RUN_ID','')) is not None,'run identity')

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=')
def normalize_key(key):
    require(isinstance(key,str) and 0<len(key)<32768,'key unavailable')
    # Normalize only harmless transport whitespace; never reconstruct missing data.
    key=key.strip(' \t\r\n')
    if key.startswith('\ufeff'): key=key[1:].strip(' \t\r\n')
    key=key.replace('\r\n','\n')
    key='\n'.join(line.strip(' \t') for line in key.split('\n'))
    if '\\n' in key or '\\r' in key: raise Hold('PEM literal newline escapes')
    import re
    match=re.fullmatch(r'-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\n([A-Za-z0-9+/=\n]+)\n-----END \1-----',key)
    require(match is not None,'PEM envelope or line structure')
    try:
        body=match.group(2).replace('\n','')
        require(bool(base64.b64decode(body,validate=True)),'PEM body empty')
    except (ValueError,TypeError): raise Hold('PEM body invalid') from None
    return (key+'\n').encode('ascii')

def jwt(key, now=None):
    key=normalize_key(key)
    now=int(time.time() if now is None else now)
    message=b64(b'{"alg":"RS256","typ":"JWT"}')+b'.'+b64(json.dumps({'iat':now-60,'exp':now+480,'iss':str(APP)},separators=(',',':')).encode())
    # Validate decoding and RSA integrity with no named files or diagnostic output.
    opts=dict(stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin'},timeout=10,check=False)
    parsed=subprocess.run(['/usr/bin/openssl','pkey','-inform','PEM','-noout','-passin','pass:'],input=key,**opts)
    require(parsed.returncode==0,'PEM private key decode failed')
    checked=subprocess.run(['/usr/bin/openssl','rsa','-inform','PEM','-check','-noout','-passin','pass:'],input=key,**opts)
    require(checked.returncode==0 and b'RSA key ok' in checked.stdout,'RSA private key validation failed')
    # Linux runner: key lives in anonymous memory-backed FD, never a named file.
    fd=os.memfd_create('gov-auth-key',os.MFD_CLOEXEC)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream: stream.write(key)
        os.lseek(fd,0,os.SEEK_SET)
        p=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',f'/proc/self/fd/{fd}','-passin','pass:','-sigopt','rsa_padding_mode:pkcs1'],input=message,pass_fds=(fd,),**opts)
        require(p.returncode==0,'RSA signing process failed')
        require(len(p.stdout)>=256,'RSA signature below 2048 bits')
        return (message+b'.'+b64(p.stdout)).decode('ascii')
    finally: os.close(fd)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class Transport:
    def __init__(self,opener=None): self.opener=opener or build_opener(NoRedirect())
    def request(self,method,path,credential,body=None):
        fixed={'/app','/app/installations?per_page=100','/repos/'+REPO+'/installation','/installation/repositories?per_page=100'}
        token_path=re.fullmatch(r'/app/installations/[1-9][0-9]{0,19}/access_tokens',path)
        allowed=(method=='GET' and path in fixed and body is None) or (method=='POST' and token_path and body=={'permissions':READ_PERMS}) or (method=='DELETE' and path=='/installation/token' and body is None)
        require(allowed,'transport route or payload')
        require(isinstance(credential,str) and credential and not any(c.isspace() for c in credential),'credential invalid')
        url='https://api.github.com'+path
        headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Registro-Docente-Governance-Auth-Probe','Authorization':'Bearer '+credential}
        if body is not None: headers['Content-Type']='application/json'
        req=Request(url, data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
        with self.opener.open(req,timeout=20) as f:
            require(f.geturl()==url,'response endpoint')
            require(f.status=={'GET':200,'POST':201,'DELETE':204}[method],'response status')
            require('rel="next"' not in f.headers.get('Link',''),'pagination not exhausted')
            data=f.read(4_000_001); require(len(data)<=4_000_000,'response too large')
            return None if method=='DELETE' else json.loads(data)

def owner(record): return (record['login'],record['id'])==OWNER

def probe(credential,request):
    app=request('GET','/app',credential)
    require(app['id']==APP and owner(app['owner']),'App identity')
    require(app['permissions']==APP_PERMS and app['events']==[],'App permission contract')
    installations=request('GET','/app/installations?per_page=100',credential)
    require(isinstance(installations,list) and len(installations)==1,'installation count')
    i=installations[0]
    require(type(i['id']) is int and i['id']>0 and i['app_id']==APP and owner(i['account']) and i['target_id']==OWNER[1] and i['target_type']=='User','installation identity')
    require(i['repository_selection']=='selected' and i['suspended_at'] is None and i['permissions']==APP_PERMS and i['events']==[],'installation contract')
    matched=request('GET','/repos/'+REPO+'/installation',credential)
    require(matched['id']==i['id'] and matched['app_id']==APP,'repository installation identity')
    # Do NOT narrow repositories here: the point is to see the entire installed scope.
    result=request('POST',f'/app/installations/{i["id"]}/access_tokens',credential,{'permissions':READ_PERMS})
    token=result.get('token')
    require(isinstance(token,str) and token and not any(c.isspace() for c in token),'token missing')
    try:
        require(result['permissions']==READ_PERMS,'token not read-only')
        scope=request('GET','/installation/repositories?per_page=100',token)
        require(scope['total_count']==len(scope['repositories'])==1,'installation scope')
        r=scope['repositories'][0]
        require((r['id'],r['full_name'])==(RID,REPO),'repository identity')
    finally:
        request('DELETE','/installation/token',token)
    return {'state':'AUTH_SCOPE_PASS','app_id':APP,'installation_id':i['id'],'repository_count':1,'token_revoked':True,'check_published':False,'release_authorized':False}

if __name__=='__main__':
    try:
        guard(os.environ)
        key=os.environ.pop('GOV_APP_PRIVATE_KEY','')
        credential=jwt(key); del key
        print(json.dumps(probe(credential,Transport().request),sort_keys=True))
    except (Hold,URLError,OSError,ValueError,TypeError,KeyError,IndexError,subprocess.SubprocessError) as e:
        # Never render exception data from HTTP, keys, or credentials.
        print('HOLD: '+(str(e) if isinstance(e,Hold) else type(e).__name__))
        raise SystemExit(1)
