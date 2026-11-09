#!/usr/bin/env python3
"""Owned RealNet cleanup gate; resources live only in dedicated namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import uuid

SOURCE=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(SOURCE/'multinode'),str(SOURCE/'runtime'),str(Path(__file__).parent)]
from dnlab_multinode.services.realnet_cleanup import PROGRAM,scope
from dnlab_multinode.services.realnet_cleanup_host import bridge_create_argv,link_identity
from dnlab_multinode.services import lab_cleanup,state as state_svc
from dnlab_multinode.models.state import DeploymentState,RealNetState
from dnlab_runtime.backend import Docker
from realnet_reflector_smoke import cleanup_container


def command(args):
    value=subprocess.run(args,text=True,capture_output=True,timeout=40)
    if value.returncode:raise RuntimeError('fixture command failed: '+shlex.join(args[:5])+' '+value.stderr.strip())
    return value.stdout.strip()


WORKER='''import json,os,signal,subprocess,sys
module={'__name__':'fixture_worker'}
exec(compile(sys.argv[1],'realnet_cleanup_host.py','exec'),module)
plan=json.loads(sys.argv[2]);directory=sys.argv[3];action=sys.argv[4];position=int(sys.argv[5]);moment=sys.argv[6]
count=0
original=module['execute']
def run(argv):
 global count
 mutation=argv[:4]==['ip','link','delete','dev'] or argv[:2] in (['docker','kill'],['docker','rm']) or argv[:4]==['iptables','-w','5','-D']
 if mutation:
  count+=1
  if count==position and moment=='before':os.kill(os.getpid(),signal.SIGKILL)
 result=original(argv)
 if mutation and count==position and moment=='after':os.kill(os.getpid(),signal.SIGKILL)
 return result
worker=module['Worker'](plan,run=run,directory=directory,attachment_directory=directory+'/attachments')
print(json.dumps(getattr(worker,action)()))
'''


def identity_comparison(plan,links):
    current={link['ifname']:link for link in links}
    comparison={}
    for name,expected in plan['links'].items():
        link=current.get(name)
        actual=None if link is None else {'identity':link_identity(link),
            'kind':link.get('linkinfo',{}).get('info_kind'),
            'config':{key:link.get('linkinfo',{}).get('info_data',{}).get(key) for key in expected['config']}}
        fields=[] if actual is None else [key for key in expected['identity'] if actual['identity'][key]!=expected['identity'][key]]
        comparison[name]={'expected':expected,'actual':actual,'changed_identity_fields':fields}
    return comparison


def snapshot_differences(expected,actual,path='snapshot'):
    if expected==actual:return []
    differences=[]
    if isinstance(expected,dict) and isinstance(actual,dict):
        for key in sorted(set(expected)|set(actual)):
            if key not in expected or key not in actual:
                differences.append({'path':path+'.'+key,'expected':expected.get(key,{'missing':True}),
                                    'actual':actual.get(key,{'missing':True})})
            else:differences.extend(snapshot_differences(expected[key],actual[key],path+'.'+key))
    elif isinstance(expected,list) and isinstance(actual,list) and len(expected)==len(actual):
        for index,(left,right) in enumerate(zip(expected,actual)):
            differences.extend(snapshot_differences(left,right,f'{path}[{index}]'))
    else:differences.append({'path':path,'expected':expected,'actual':actual})
    return differences


def invariant_differences(expected,actual):
    """Allow numeric drift only at the two diagnosed kernel timer paths."""
    allowed=set()
    for index,(left,right) in enumerate(zip(expected.get('links',[]),actual.get('links',[]))):
        if left.get('ifname')!=right.get('ifname'):continue
        before=left.get('linkinfo',{});after=right.get('linkinfo',{})
        if before.get('info_kind')==after.get('info_kind')=='bridge':
            allowed.add(f'snapshot.links[{index}].linkinfo.info_data.gc_timer')
        if (before.get('info_kind')==after.get('info_kind')=='vxlan'
                and before.get('info_slave_kind')==after.get('info_slave_kind')=='bridge'):
            allowed.add(f'snapshot.links[{index}].linkinfo.info_slave_data.forward_delay_timer')
    return [difference for difference in snapshot_differences(expected,actual)
            if not (difference['path'] in allowed and all(type(difference[key]) in (int,float)
                    and difference[key]>=0 for key in ('expected','actual')))]


def run(image,case_limit=14,automatic_bridge_mac=False,daemon_recovery=False):
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-cleanup-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8];names=['drsp-rnc-'+token+'-'+side for side in ('a','b')]
    namespaces={};containers=[];plans={};api=Docker();report={'scope':'local-isolated-RealNet-cleanup','status':'running','cases':[],'requested_cases':case_limit,'bridge_MAC':'automatic' if automatic_bridge_mac else 'explicit-at-create','production_hosts_qualified':False}
    def ns(name,*args):return command(['ip','netns','exec',name,*args])
    def worker(name,plan,action='cleanup',position=0,moment='after'):
        return subprocess.run(['ip','netns','exec',name,'python3','-c',WORKER,PROGRAM,json.dumps(plan),str(root/name/plan['scope']),action,str(position),moment],text=True,capture_output=True,timeout=40)
    def create(name,index,ownership_scope=None):
        value=ownership_scope or scope('fixture-'+token,str(index),name);alias='dnlab-runtime:realnet:'+value+':'+uuid.uuid4().hex
        create_bridge=['ip','link','add','br-test','type','bridge'] if automatic_bridge_mac else bridge_create_argv('br-test',alias.rsplit(':',1)[1])
        ns(name,*create_bridge)
        ns(name,'ip','link','add','vx-test','type','vxlan','id','42001','local','198.18.211.1','remote','198.18.211.2','dstport','14789','dev','drsp-u')
        container_name='drsp-rnc-'+token+'-'+str(index)
        labels={'org.dnlab.realnet.scope':value,'org.dnlab.realnet.creator':uuid.uuid4().hex,'io.dnlab.spike':token}
        args=['docker','run','-d','--network','none','--name',container_name]
        for key,label in labels.items():args+=['--label',key+'='+label]
        identity=command([*args,image]);original=api.inspect(identity);containers.append(original)
        ns(name,'ip','link','add','vh-test','type','veth','peer','name','drsp-peer')
        ns(name,'ip','link','set','drsp-peer','netns',str(original['State']['Pid']))
        for port in ('vx-test','vh-test'):ns(name,'ip','link','set',port,'master','br-test')
        for port in ('br-test','vx-test','vh-test'):
            ns(name,'ip','link','set',port,'alias',alias);ns(name,'ip','link','set',port,'up')
        firewall=[['FORWARD',direction,'br-test','-m','comment','--comment',alias,'-j','ACCEPT'] for direction in ('-i','-o')]
        for rule in firewall:ns(name,'iptables','-w','5','-A',*rule)
        # Foreign accept on the same bridge must survive owned cleanup.
        ns(name,'iptables','-w','5','-A','FORWARD','-i','br-test','-j','ACCEPT')
        links=json.loads(ns(name,'ip','-j','-d','link','show'))
        context=json.loads(ns(name,'python3','-c',"import json,os; p=os.stat('/proc/self/ns/net'); print(json.dumps({'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),'device':p.st_dev,'inode':p.st_ino}))"))
        proof={x['ifname']:{'identity':link_identity(x),'kind':x['linkinfo']['info_kind'],
                           'config':{key:x['linkinfo'].get('info_data',{})[key] for key in ('id','local','remote','dstport') if key in x['linkinfo'].get('info_data',{})} if x['ifname']=='vx-test' else {}}
               for x in links if x['ifname'] in ('br-test','vx-test','vh-test')}
        if not automatic_bridge_mac:assert proof['br-test']['identity']['address']==create_bridge[5]
        plan={'scope':value,'context':context,'links':proof,'router':{'id':identity,'name':container_name,'image':original['Image'],'labels':original['Config']['Labels']},'firewall':firewall}
        plans[name]=plan
        return plan
    def snapshot(name,plan):
        router=api.inspect(plan['router']['id'])
        return {'links':json.loads(ns(name,'ip','-j','-d','link','show')),'router_id':router['Id'] if router else None,
                'started_at':router['State']['StartedAt'] if router else None,'firewall':[line for line in ns(name,'iptables-save','-t','filter').splitlines() if not line.startswith('#')]}
    def clean_verified(name,plan):
        result=worker(name,plan)
        if result.returncode:raise RuntimeError('cleanup worker failed: '+result.stderr.strip())
        assert json.loads(result.stdout)['status']=='cleaned'
        assert api.inspect(plan['router']['id']) is None
        assert not {x['ifname'] for x in json.loads(ns(name,'ip','-j','link','show'))}&set(plan['links'])
        rules=ns(name,'iptables-save','-t','filter');assert '-A FORWARD -i br-test -j ACCEPT' in rules
        assert all(rule[6] not in rules for rule in plan['firewall'])
        ns(name,'iptables','-w','5','-D','FORWARD','-i','br-test','-j','ACCEPT')
    try:
        for name in names:
            assert not Path('/var/run/netns',name).exists()
            command(['ip','netns','add',name]);info=os.stat('/var/run/netns/'+name);namespaces[name]=(info.st_dev,info.st_ino)
            ns(name,'ip','link','set','lo','up');ns(name,'ip','link','add','drsp-u','type','dummy')
            ns(name,'ip','address','add','198.18.211.1/24','dev','drsp-u');ns(name,'ip','link','set','drsp-u','up')
        unaffected=create(names[1],99);baseline=snapshot(names[1],unaffected)
        (root/'control-snapshot-before.json').write_text(json.dumps(baseline,indent=2)+'\n')
        for index,(position,moment) in enumerate([(p,m) for p in range(1,8) for m in ('before','after')][:case_limit]):
            plan=create(names[0],index)
            for name,proof in ((names[0],plan),(names[1],unaffected)):
                preflight=worker(name,proof,'preflight');assert preflight.returncode==0,preflight.stderr
            crashed=worker(names[0],plan,position=position,moment=moment)
            assert crashed.returncode==-signal.SIGKILL,(crashed.returncode,crashed.stderr)
            journal=json.loads((root/names[0]/plan['scope']/(plan['scope']+'.json')).read_text())
            assert journal['phase']=='cleanup_pending' and 'intent' in journal['steps'].values()
            clean_verified(names[0],plan)
            retry=worker(names[0],plan);assert retry.returncode==0,retry.stderr
            current=snapshot(names[1],unaffected)
            raw_differences=snapshot_differences(baseline,current)
            differences=invariant_differences(baseline,current)
            (root/'control-snapshot-after.json').write_text(json.dumps(current,indent=2)+'\n')
            (root/'control-snapshot-differences.json').write_text(json.dumps(raw_differences,indent=2)+'\n')
            (root/'control-snapshot-invariant-differences.json').write_text(json.dumps(differences,indent=2)+'\n')
            assert not differences,'control lab snapshot differs at: '+', '.join(value['path'] for value in differences)
            report['cases'].append({'mutation':position,'moment':moment,'SIGKILL_verified':True,'recovery':'cleaned','other_lab_unchanged':True,
                                    'operational_timer_differences':raw_differences})
        if daemon_recovery:
            class NamespaceClient:
                name='master'
                host='local-isolated-fixture'
                def run(self,text):
                    argv=shlex.split(text)
                    if argv[:2]==['python3','-c'] and argv[2]==PROGRAM:
                        result=worker(names[0],json.loads(argv[4]),action=argv[3])
                        if result.returncode:raise RuntimeError('fixture worker failed: '+result.stderr.strip())
                        return result.stdout.strip()
                    return ns(names[0],'/bin/sh','-c',text)
                def run_no_check(self,text,timeout=30):
                    result=subprocess.run(['ip','netns','exec',names[0],'/bin/sh','-c',text],text=True,capture_output=True,timeout=timeout)
                    return result.returncode,result.stdout,result.stderr
            clients={'master':NamespaceClient()}
            for index,position in enumerate((3,5),100):
                lab='fixture-'+token+'-daemon-'+str(position)
                plan=create(names[0],index,scope(lab,'access','master'))
                infrastructure=RealNetState(name='access',bridge='br-test',vxlan_id=42001,hosts=['master'],
                    router_container=plan['router']['name'],router_veth='vh-test',vxlan_ifaces={'master':['vx-test']},
                    resource_identities={'realnet_cleanup_v1':{'master':plan}})
                state=DeploymentState(lab_name=lab,topology_file=str(root/(lab+'.yml')),teardown_requested=True,realnets=[infrastructure])
                state_svc.save_state(state,root)
                crashed=worker(names[0],plan,position=position,moment='after')
                assert crashed.returncode==-signal.SIGKILL,(crashed.returncode,crashed.stderr)
                status=lab_cleanup._finalize_requested_teardowns({lab:state},root,None,clients=clients)
                assert 'retained' in status[lab] and state_svc.load_state(lab,root) is not None,status
                cleanup_plan=lab_cleanup.LabCleanupPlan(lab=lab)
                lab_cleanup._execute_plans({lab:cleanup_plan},clients,own_clients=False,states={lab:state},state_directory=root)
                assert not cleanup_plan.protected and not cleanup_plan.warnings,cleanup_plan.to_dict()
                operation=state_svc.load_state(lab,root).realnets[0].resource_identities['realnet_cleanup_operation']
                assert operation['phase']=='cleaned' and operation['hosts']=={'master':'cleaned'}
                status=lab_cleanup._finalize_requested_teardowns({lab:state},root,None,clients=clients)
                assert status[lab].endswith('finalized') and state_svc.load_state(lab,root) is None,status
                assert not invariant_differences(baseline,snapshot(names[1],unaffected))
                report.setdefault('daemon_cases',[]).append({'SIGKILL_after_mutation':position,'state_retained_before_recovery':True,
                    'guarded_recovery':'cleaned','state_finalized_after_journal_verification':True,'other_lab_unchanged':True})
                # Owned rules are absent; remove only the fixture's foreign rule.
                ns(names[0],'iptables','-w','5','-D','FORWARD','-i','br-test','-j','ACCEPT')
        clean_verified(names[1],unaffected)
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error)
        diagnostics={}
        for name,plan in plans.items():
            try:diagnostics[name]=identity_comparison(plan,json.loads(ns(name,'ip','-j','-d','link','show')))
            except Exception as diagnostic_error:diagnostics[name]={'error':str(diagnostic_error)}
        (root/'identity-diagnostic.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
        report['identity_diagnostic']=str(root/'identity-diagnostic.json')
        raise
    finally:
        try:
            for original in reversed(containers):cleanup_container(api,original)
            for name,identity in namespaces.items():
                info=os.stat('/var/run/netns/'+name);assert (info.st_dev,info.st_ino)==identity
                command(['ip','netns','delete',name]);assert not Path('/var/run/netns',name).exists()
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified'),'error':report.get('error')}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');parser.add_argument('--image',required=True)
    parser.add_argument('--case-limit',type=int,choices=range(1,15),default=14)
    parser.add_argument('--automatic-bridge-mac',action='store_true',help='Reproduce the unsafe fixture bootstrap for diagnostics')
    parser.add_argument('--daemon-recovery',action='store_true',help='Qualify daemon recovery and finalization after two additional real crashes');args=parser.parse_args()
    if not args.execute:print(json.dumps({'mutations_performed':False,'creates':'two dedicated namespaces and up to fifteen owned helper containers'}))
    elif os.geteuid()!=0:raise RuntimeError('fixture requires root')
    else:run(args.image,args.case_limit,args.automatic_bridge_mac,args.daemon_recovery)
