import unittest, copy, os, subprocess, tempfile, json, base64
import auth_probe as a

class Tests(unittest.TestCase):
    def fixture(self):
        own={'login':a.OWNER[0],'id':a.OWNER[1]}
        i={'id':42,'app_id':a.APP,'account':own,'target_id':a.OWNER[1],'target_type':'User','repository_selection':'selected','suspended_at':None,'permissions':copy.deepcopy(a.APP_PERMS),'events':[]}
        return {'/app':{'id':a.APP,'owner':own,'permissions':copy.deepcopy(a.APP_PERMS),'events':[]},'/app/installations?per_page=100':[i],'/repos/'+a.REPO+'/installation':copy.deepcopy(i),'/app/installations/42/access_tokens':{'token':'synthetic','permissions':copy.deepcopy(a.READ_PERMS)},'/installation/repositories?per_page=100':{'total_count':1,'repositories':[{'id':a.RID,'full_name':a.REPO}]},'/installation/token':None}
    def run_probe(self,d,calls):
        def request(m,p,c,b=None):
            calls.append((m,p,c,b))
            return d[p]
        return a.probe('fake-jwt',request)
    def test_valid(self):
        calls=[]; r=self.run_probe(self.fixture(),calls)
        self.assertEqual(r['state'],'AUTH_SCOPE_PASS'); self.assertFalse(r['check_published']); self.assertTrue(r['token_revoked'])
        self.assertEqual([x[0] for x in calls],['GET','GET','GET','POST','GET','DELETE'])
        self.assertEqual(calls[3][3],{'permissions':a.READ_PERMS}); self.assertEqual(calls[-1][2],'synthetic')
    def test_app_and_installation_fail_closed(self):
        for mutate in [lambda d:d['/app'].update(id=7),lambda d:d['/app']['owner'].update(id=2),lambda d:d['/app']['permissions'].update(administration='write'),lambda d:d['/app'].update(events=['push']),lambda d:d['/app/installations?per_page=100'].clear(),lambda d:d['/app/installations?per_page=100'].append({}),lambda d:d['/app/installations?per_page=100'][0].update(repository_selection='all'),lambda d:d['/app/installations?per_page=100'][0].update(suspended_at='date'),lambda d:d['/app/installations?per_page=100'][0].update(target_id=8),lambda d:d['/repos/'+a.REPO+'/installation'].update(id=8)]:
            with self.subTest(mutate=mutate):
                d=self.fixture(); mutate(d); calls=[]
                with self.assertRaises(a.Hold): self.run_probe(d,calls)
                self.assertFalse(any(c[0]=='POST' for c in calls))
    def test_scope_and_permissions_failure_revokes(self):
        for mutate in [lambda d:d['/app/installations/42/access_tokens']['permissions'].update(checks='write'),lambda d:d['/installation/repositories?per_page=100'].update(total_count=2),lambda d:d['/installation/repositories?per_page=100']['repositories'][0].update(id=0),lambda d:d['/installation/repositories?per_page=100']['repositories'][0].update(full_name='other/repo')]:
            with self.subTest(mutate=mutate):
                d=self.fixture(); mutate(d); calls=[]
                with self.assertRaises(a.Hold): self.run_probe(d,calls)
                self.assertEqual(calls[-1][0:2],('DELETE','/installation/token'))
    def test_revoke_failure_no_pass(self):
        d=self.fixture(); del d['/installation/token']; calls=[]
        with self.assertRaises(KeyError): self.run_probe(d,calls)
    def test_context(self):
        env={'GITHUB_REPOSITORY':a.GOV,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_REF':a.GOV+'/'+a.WORKFLOW+'@refs/heads/main','GITHUB_ACTOR_ID':str(a.OWNER[1]),'GITHUB_TRIGGERING_ACTOR':a.OWNER[0],'GITHUB_RUN_ID':'42','GOV_ADMISSION_MODE':'authenticate'}
        a.guard(env)
        for key in env:
            with self.subTest(key=key):
                bad=dict(env); bad[key]='invalid'
                with self.assertRaises(a.Hold): a.guard(bad)
    def test_transport_denies_publication(self):
        t=a.Transport()
        for m,p,b in [('POST','/repos/'+a.REPO+'/check-runs',{}),('POST','/app/installations/42/access_tokens',{'permissions':a.APP_PERMS}),('POST','/app/installations/42/access_tokens',{'permissions':a.READ_PERMS,'repository_ids':[a.RID]}),('GET','/repos/other/repo',None),('DELETE','/repos/'+a.REPO,None)]:
            with self.subTest(p=p,m=m):
                with self.assertRaises(a.Hold): t.request(m,p,'synthetic',b)
    def test_rsa_signature_real_synthetic_key(self):
        key=subprocess.check_output(['/usr/bin/openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'],stderr=subprocess.DEVNULL)
        pub=subprocess.check_output(['/usr/bin/openssl','pkey','-pubout'],input=key,stderr=subprocess.DEVNULL)
        head,payload,sig=a.jwt(key.decode(),now=1000).split('.')
        dec=lambda x:base64.urlsafe_b64decode(x+'='*(-len(x)%4))
        self.assertEqual(json.loads(dec(payload)),{'iat':940,'exp':1480,'iss':str(a.APP)})
        with tempfile.TemporaryDirectory() as td:
            for name,data in [('pub.pem',pub),('sig',dec(sig))]:
                with open(os.path.join(td,name),'wb') as f:f.write(data)
            result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-verify',td+'/pub.pem','-signature',td+'/sig'],input=(head+'.'+payload).encode(),capture_output=True)
            self.assertEqual(result.returncode,0)
        with self.assertRaises(a.Hold): a.jwt('invalid')

    def test_pem_transport_and_diagnostics(self):
        def openssl(*args,data=None):
            return subprocess.check_output(['/usr/bin/openssl',*args],input=data,stderr=subprocess.DEVNULL)
        key=openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048')
        pem=openssl('pkey','-traditional',data=key).decode()
        variants=[key.decode(),pem,pem.replace('\n','\r\n'),pem.rstrip('\n'),'  '+pem+'  ','\ufeff'+pem,pem.replace('\n','\n ',1)]
        expected=a.jwt(pem,now=1000)
        for variant in variants:
            with self.subTest(case='transport'):
                self.assertEqual(a.jwt(variant,now=1000),expected)
        ec=openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256').decode()
        small=openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:1024').decode()
        enc=openssl('pkcs8','-topk8','-passout','pass:synthetic',data=key).decode()
        pss=openssl('genpkey','-algorithm','RSA-PSS','-pkeyopt','rsa_keygen_bits:2048').decode()
        cases=[('', 'key unavailable'),(pem.replace('\n','\\n'),'PEM literal newline escapes'),(' '.join(pem.splitlines()),'PEM envelope or line structure'),('\n'.join(pem.splitlines()[:2]+pem.splitlines()[3:])+'\n','PEM private key decode failed'),('\n'.join(pem.splitlines()[:-1]),'PEM envelope or line structure'),(ec,'RSA private key validation failed'),(small,'RSA signature below 2048 bits'),(enc,'PEM envelope or line structure'),(pem.replace('-','–'),'PEM envelope or line structure'),(pss,'RSA signing process failed'),('-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----','PEM body invalid')]
        for variant,label in cases:
            with self.subTest(expected=label):
                with self.assertRaises(a.Hold) as ctx: a.jwt(variant,now=1000)
                if variant == pss:
                    # OpenSSL versions reject RSA-PSS at validation or PKCS#1 signing.
                    # Only these two rejection stages are valid; success is never accepted.
                    self.assertIn(str(ctx.exception), ('RSA private key validation failed', 'RSA signing process failed'))
                else:
                    self.assertEqual(str(ctx.exception),label)

if __name__=='__main__': unittest.main(verbosity=2)
