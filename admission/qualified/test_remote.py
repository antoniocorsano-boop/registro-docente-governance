import unittest, copy
import verify_remote as v

def fixture():
    p={'number':416,'state':'open','merged':False,'head':{'sha':v.HEAD,'ref':v.BRANCH,'repo':{'id':v.RID,'full_name':v.REPO}},'base':{'sha':v.BASE,'ref':'main','repo':{'id':v.RID,'full_name':v.REPO}}}
    data={'pulls/416':p,'branches/main':{'name':'main','commit':{'sha':v.BASE},'protected':True},'git/commits/'+v.HEAD:{'sha':v.HEAD,'parents':[{'sha':v.PARENT}],'tree':{'sha':v.TREE}},'git/trees/'+v.TREE+'?recursive=1':{'sha':v.TREE,'truncated':False,'tree':[{'path':k,'sha':s,'mode':'100644','type':'blob'} for k,s in v.ENTRIES.items()]}}
    checks=[]
    for run,(wid,names) in v.RUNS.items():
        data['actions/runs/'+str(run)]={'id':run,'workflow_id':wid,'head_sha':v.HEAD,'head_branch':v.BRANCH,'event':'pull_request','run_attempt':1,'status':'completed','conclusion':'success','repository':{'id':v.RID},'head_repository':{'id':v.RID},'check_suite_id':run+1,'pull_requests':[copy.deepcopy(p)]}
        jobs=[]
        for name in names:
            ident=len(checks)+1
            jobs.append({'id':ident,'name':name,'run_id':run,'head_sha':v.HEAD,'status':'completed','conclusion':'success'})
            checks.append({'id':ident,'name':name,'app':{'id':v.APP},'head_sha':v.HEAD,'status':'completed','conclusion':'success','check_suite':{'id':run+1}})
        data['actions/runs/'+str(run)+'/jobs?per_page=100']={'total_count':len(jobs),'jobs':jobs}
    data['commits/'+v.HEAD+'/check-runs?per_page=100&filter=latest']={'total_count':len(checks),'check_runs':checks}
    return data
class TestRemote(unittest.TestCase):
    def test_valid(self): self.assertEqual(v.verify(fixture().__getitem__)['jobs'],23)
    def test_fail_closed(self):
        c='git/commits/'+v.HEAD; t='git/trees/'+v.TREE+'?recursive=1'; w='actions/runs/45937846157'; j=w+'/jobs?per_page=100'; k='commits/'+v.HEAD+'/check-runs?per_page=100&filter=latest'
        variants=[('head',lambda d:d['pulls/416']['head'].update(sha='other')),('base',lambda d:d['pulls/416']['base'].update(sha='other')),('repo',lambda d:d['pulls/416']['head']['repo'].update(id=0)),('merged',lambda d:d['pulls/416'].update(merged=True)),('protection',lambda d:d['branches/main'].update(protected=False)),('parent',lambda d:d[c]['parents'].append({'sha':'other'})),('tree',lambda d:d[c]['tree'].update(sha='other')),('truncated',lambda d:d[t].update(truncated=True)),('script blob',lambda d:d[t]['tree'][-1].update(sha='other')),('script mode',lambda d:d[t]['tree'][-1].update(mode='100755')),('workflow attempt',lambda d:d[w].update(run_attempt=2)),('workflow event',lambda d:d[w].update(event='push')),('workflow identity',lambda d:d[w].update(workflow_id=0)),('missing PR',lambda d:d[w].update(pull_requests=[])),('skipped job',lambda d:d[j]['jobs'][0].update(conclusion='skipped')),('missing job',lambda d:d[j]['jobs'].pop()),('wrong job sha',lambda d:d[j]['jobs'][0].update(head_sha='other')),('wrong app',lambda d:d[k]['check_runs'][0]['app'].update(id=0)),('wrong suite',lambda d:d[k]['check_runs'][0]['check_suite'].update(id=0)),('duplicate check',lambda d:(d[k]['check_runs'].append(copy.deepcopy(d[k]['check_runs'][0])),d[k].update(total_count=24))),('incomplete page',lambda d:d[k].update(total_count=24))]
        for name,change in variants:
            with self.subTest(name=name):
                d=fixture(); change(d)
                with self.assertRaises(v.Denied): v.verify(d.__getitem__)
    def test_race(self):
        d=fixture(); n=0
        def get(p):
            nonlocal n
            if p=='pulls/416':
                n+=1
                if n==2: d[p]['head']['sha']='other'
            return d[p]
        with self.assertRaises(v.Denied): v.verify(get)
if __name__=='__main__':unittest.main(verbosity=2)
