#!/usr/bin/env python3
"""Native data-only RealNet attachment/recovery in a private host namespace."""
import argparse
import copy
import json
import multiprocessing
import os
import re
from pathlib import Path
import signal
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import uuid

SOURCE=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(SOURCE/'multinode'),str(SOURCE/'runtime')]
from dnlab_multinode.services.realnet_attachment_host import Worker,AttachmentError,signature
from dnlab_multinode.services.realnet_cleanup import scope
from dnlab_runtime.journal import Journal
from dnlab_runtime.bridge import BridgeManager,BridgeLinux
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.vxlan import VxlanManager,VxlanLinux
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.manifest import Conflict


def run(image,teardown_recovery=False,generations=False):
    if not re.fullmatch('sha256:[0-9a-f]{64}',image):raise ValueError('full local immutable image ID required')
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-data-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8];namespace='drsp-rndata-'+token
    containers={};owned_ns=None
    report={'status':'running','scope':'isolated native VD data attachments; no NOS or production SSH','image':image}
    def save(): (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    def command(args,**kwargs):
        r=subprocess.run(args,text=True,capture_output=True,timeout=35,**kwargs)
        if r.returncode:raise RuntimeError('fixture command failed: '+args[0]+' '+r.stderr.strip())
        return r.stdout
    def ns(*args,**kwargs):
        current=os.stat('/var/run/netns/'+namespace)
        assert (current.st_dev,current.st_ino)==owned_ns
        return command(['ip','netns','exec',namespace,*args],**kwargs)
    def vd(role,*args):
        c=containers[role];v=json.loads(command(['docker','inspect',c['Id']]))[0]
        assert (v['Id'],v['Image'],v['Config']['Labels'],v['State']['StartedAt'])==(c['Id'],c['Image'],c['Config']['Labels'],c['State']['StartedAt'])
        return command(['nsenter','-t',str(c['State']['Pid']),'-n',*args])
    def links():return json.loads(ns('ip','-j','-d','link','show'))
    def selected(role,name):return next(v for v in json.loads(vd(role,'ip','-j','-d','link','show')) if v['ifname']==name)
    def context():
        return json.loads(ns('python3','-c',"import os,json;from pathlib import Path;s=os.stat('/proc/self/ns/net');print(json.dumps({'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'device':s.st_dev,'inode':s.st_ino}))"))
    def execute(args,**kwargs):
        if args[:2]==['docker','inspect'] or args[:2]==['docker','exec']:return command(args,**kwargs)
        return ns(*args,**kwargs)
    proofs={}
    def worker(role,callback=execute):
        value=Worker(proofs[role],directory=root/'journal',run=callback,host_context=context)
        path=root/'journal'/'journal.sqlite3'
        # Fixture acts as an explicit recovery operator reading the root intent.
        if path.exists():
            with closing(sqlite3.connect(path)) as db, db:
                row=db.execute('SELECT payload FROM realnet_attachments WHERE id=?',(value.key,)).fetchone()
                if row:value.attempt=Worker.attempt_id(json.loads(row[0]))
        return value
    def invariant():
        values={x['ifname']:x for x in links()}
        return {'control':signature(values['drsp-c']), 'control_master':values['drsp-c'].get('master'),
                'bridges':{name:signature(values[name]) for name in ('drsp-br','drsp-ctrl')},
                'management':{role:signature(selected(role,'eth0')) for role in containers},
                'containers':{role:json.loads(command(['docker','inspect',c['Id']]))[0]['State']['StartedAt'] for role,c in containers.items()}}
    def ping():vd('a','ping','-c','1','-W','2','192.0.2.2')
    try:
        command(['ip','netns','add',namespace]);info=os.stat('/var/run/netns/'+namespace);owned_ns=(info.st_dev,info.st_ino)
        for name,rn in [('drsp-br','access'),('drsp-ctrl','control')]:
            creator=uuid.uuid4().hex
            ns('ip','link','add',name,'address','02:12:34:56:78:'+('01' if rn=='access' else '02'),'type','bridge')
            ns('ip','link','set',name,'alias','dnlab-runtime:realnet:'+scope('lab',rn,'master')+':'+creator)
            ns('ip','link','set',name,'up')
        for role in ('a','b','c'):
            name='drsp-rndata-'+token+'-'+role;labels={'org.dnlab.fixture':token,'org.dnlab.role':role}
            identity=command(['docker','run','--pull','never','-d','--network','none','--name',name,
                              '--label','org.dnlab.fixture='+token,'--label','org.dnlab.role='+role,
                              '--entrypoint','python3',image,'-c','import time;time.sleep(3600)']).strip()
            c=json.loads(command(['docker','inspect',identity]))[0];containers[role]=c
            assert c['Config']['Labels']==labels and c['State']['Running']
            fd=os.open(f"/proc/{c['State']['Pid']}/ns/net",os.O_RDONLY)
            try:ns('ip','link','add','drsp-'+role,'type','veth','peer','name','eth1','netns','/proc/self/fd/'+str(fd),pass_fds=(fd,))
            finally:os.close(fd)
            ns('ip','link','set','drsp-'+role,'alias','dnlab-runtime:vd:'+token+':'+role)
            vd(role,'ip','link','add','eth0','type','dummy');vd(role,'ip','link','set','eth0','up')
            vd(role,'ip','link','set','eth1','up');vd(role,'ip','address','add',{'a':'192.0.2.1/24','b':'192.0.2.2/24','c':'198.51.100.1/24'}[role],'dev','eth1')
            bridge='drsp-ctrl' if role=='c' else 'drsp-br';rn='control' if role=='c' else 'access'
            inventory={v['ifname']:v for v in links()};ni=os.stat(f"/proc/{c['State']['Pid']}/ns/net")
            proofs[role]={'lab':'lab','node':role,'realnet':rn,'host':'master','link':'rn-'+role,'management_interface':'eth0','context':context(),
                          'source':signature(inventory['drsp-'+role]),'peer':signature(selected(role,'eth1')),
                          'namespace':{'device':ni.st_dev,'inode':ni.st_ino},'bridge':signature(inventory[bridge]),
                          'container':{'id':c['Id'],'name':name,'image':c['Image'],'labels':labels,'started_at':c['State']['StartedAt']}}
        for role in containers:worker(role).operate('create')
        ping();before=invariant();report['control_expected']=before;report['crashes']=[]
        # The actual custom primitives must consult the same active reservation.
        class Linux:
            def run(self,args):return execute(args)
            def network_identity(self):return context()
        journal=Journal(root/'journal')
        try:
            inventory={v['ifname']:v for v in links()}
            for manager,identity,kwargs in (
                (BridgeManager(journal,BridgeLinux(Linux())),BridgeIdentity('other','l0'),{'sources':[inventory['drsp-a'],inventory['drsp-b']],'mtu':1500}),
                (VxlanManager(journal,VxlanLinux(Linux())),VxlanIdentity('other','vx0','drsp-a',12345),{'source':inventory['drsp-a'],'underlay':'unused','local':'198.18.0.1','remote':'198.18.0.2','mtu':1450})):
                try:manager.create(identity,**kwargs)
                except Conflict as error:assert 'reserved' in str(error)
                else:raise RuntimeError('custom link bypassed RealNet reservation')
            assert invariant()==before;ping();report['shared_bridge_vxlan_reservation']=True
        finally:journal.close()

        # Before/after each create and cleanup mutation; fresh worker after SIGKILL.
        worker('a').operate('delete')
        for action in ('create','delete'):
            for target in (1,2):
                for when in ('before','after'):
                    if action=='delete':worker('a').operate('create')
                    def child():
                        count=0
                        def crash(args,**kwargs):
                            nonlocal count
                            mutation=args[:3]==['ip','link','set']
                            if mutation:
                                count+=1
                                if count==target and when=='before':os.kill(os.getpid(),signal.SIGKILL)
                            value=execute(args,**kwargs)
                            if mutation and count==target and when=='after':os.kill(os.getpid(),signal.SIGKILL)
                            return value
                        worker('a',crash).operate(action)
                    process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(30)
                    if process.is_alive():process.kill();process.join();raise RuntimeError('owned worker timeout')
                    assert process.exitcode==-signal.SIGKILL
                    worker('a').operate('recover')
                    report['control_actual']=invariant();assert report['control_actual']==before
                    worker('a').operate('create');ping();worker('a').operate('delete')
                    report['crashes'].append({'action':action,'step':target,'when':when,'recovered':True})
        worker('a').operate('create');ping()
        # Foreign same-name replacement must refuse before touching it or carriers.
        replacement=copy.deepcopy(proofs['a']);replacement['source']['address']='02:ff:ff:ff:ff:ff'
        try:Worker(replacement,directory=root/'journal',run=execute,host_context=context).operate('delete')
        except AttachmentError:pass
        else:raise RuntimeError('foreign endpoint accepted')
        assert invariant()==before;ping()
        if generations:
            report['generation_crashes']=[]
            old_proofs=[]
            for when in ('before','after'):
                worker('a').operate('delete');old_proof=copy.deepcopy(proofs['a']);old_proofs.append(old_proof)
                old_container=containers['a'];old_token=worker('a').attempt
                other_before={role:{'container':containers[role]['Id'],'data':signature(selected(role,'eth1')),
                                    'management':signature(selected(role,'eth0'))} for role in ('b','c')}
                vd('a','ip','-j','link','show')  # Verify immutable identity before explicit fixture removal.
                command(['docker','kill','--signal','KILL',old_container['Id']]);command(['docker','wait',old_container['Id']]);command(['docker','rm',old_container['Id']])
                containers.pop('a')
                assert not any(v['ifname']=='drsp-a' for v in links())
                name=old_container['Name'].lstrip('/');labels={'org.dnlab.fixture':token,'org.dnlab.role':'a','org.dnlab.generation':when}
                identity=command(['docker','run','--pull','never','-d','--network','none','--name',name,
                                  '--label','org.dnlab.fixture='+token,'--label','org.dnlab.role=a','--label','org.dnlab.generation='+when,
                                  '--entrypoint','python3',image,'-c','import time;time.sleep(3600)']).strip()
                container=json.loads(command(['docker','inspect',identity]))[0];containers['a']=container
                assert container['Id']!=old_container['Id'] and container['Config']['Labels']==labels
                fd=os.open(f"/proc/{container['State']['Pid']}/ns/net",os.O_RDONLY)
                try:ns('ip','link','add','drsp-a','type','veth','peer','name','eth1','netns','/proc/self/fd/'+str(fd),pass_fds=(fd,))
                finally:os.close(fd)
                ns('ip','link','set','drsp-a','alias','dnlab-runtime:vd:'+token+':a:'+when)
                vd('a','ip','link','add','eth0','type','dummy');vd('a','ip','link','set','eth0','up')
                vd('a','ip','link','set','eth1','up');vd('a','ip','address','add','192.0.2.1/24','dev','eth1')
                observed={v['ifname']:v for v in links()};ni=os.stat(f"/proc/{container['State']['Pid']}/ns/net")
                proofs['a']=dict(old_proof,source=signature(observed['drsp-a']),peer=signature(selected('a','eth1')),
                                 namespace={'device':ni.st_dev,'inode':ni.st_ino},
                                 container={'id':container['Id'],'name':name,'image':container['Image'],'labels':labels,'started_at':container['State']['StartedAt']})
                before['management']['a']=signature(selected('a','eth0'));before['containers']['a']=container['State']['StartedAt']
                def generation_child():
                    value=worker('a');original=value.save
                    def crash(db,payload,phase,**kwargs):
                        reserve=phase=='applying' and payload['step']=='reserved'
                        if reserve and when=='before':os.kill(os.getpid(),signal.SIGKILL)
                        original(db,payload,phase,**kwargs)
                        if reserve and when=='after':os.kill(os.getpid(),signal.SIGKILL)
                    value.save=crash;value.operate('create')
                process=multiprocessing.get_context('fork').Process(target=generation_child);process.start();process.join(30)
                if process.is_alive():process.kill();process.join();raise RuntimeError('owned generation worker timeout')
                assert process.exitcode==-signal.SIGKILL
                with closing(sqlite3.connect(root/'journal'/'journal.sqlite3')) as db, db:
                    raw,phase=db.execute('SELECT payload,phase FROM realnet_attachments WHERE id=?',(worker('a').key,)).fetchone()
                    payload=json.loads(raw)
                if when=='before':assert phase=='cleaned' and payload['proof']==old_proof and Worker.attempt_id(payload)==old_token
                else:
                    assert phase=='applying' and payload['proof']==proofs['a'] and Worker.attempt_id(payload)!=old_token
                    worker('a').operate('recover')
                result=worker('a').operate('create');ping()
                for previous in old_proofs:
                    obsolete=Worker(previous,directory=root/'journal',run=execute,host_context=context)
                    for action in ('create','delete','recover'):
                        try:obsolete.operate(action,expected_attempt=result['attempt'])
                        except AttachmentError:pass
                        else:raise RuntimeError('obsolete VD generation accepted')
                for role in ('b','c'):
                    assert containers[role]['Id']==other_before[role]['container']
                    assert signature(selected(role,'eth1'))==other_before[role]['data'] and signature(selected(role,'eth0'))==other_before[role]['management']
                assert invariant()==before
                with closing(sqlite3.connect(root/'journal'/'journal.sqlite3')) as db, db:
                    records=db.execute('SELECT attempt,payload,phase FROM realnet_attachment_attempts WHERE logical_id=?',(worker('a').key,)).fetchall()
                assert any(json.loads(raw)['proof']==old_proof and phase=='cleaned' for _,raw,phase in records)
                report['generation_crashes'].append({'when':when,'fresh_container':container['Id'],'old_container_removed':old_container['Id'],
                                                    'new_attempt':result['attempt'],'history_entries':len(records),'recovered':True})
            report['new_vd_generations_and_stale_request_refusal']=True
        if teardown_recovery:
            from dnlab_multinode.services.realnet_cleanup import PROGRAM
            from dnlab_multinode.services.realnet_cleanup_host import link_identity
            module={'__name__':'native_RealNet_cleanup_fixture'};exec(PROGRAM,module)
            inventory={v['ifname']:v for v in links()}
            plan={'scope':scope('lab','access','master'),'context':context(),
                  'links':{'drsp-br':{'kind':'bridge','identity':link_identity(inventory['drsp-br']),'config':{}}},
                  'router':None,'firewall':[]}
            def guard(callback=execute):
                return module['Worker'](plan,run=callback,host_context=context,
                                       directory=root/'cleanup',attachment_directory=root/'journal')
            assert guard().preflight()['status']=='verified'
            report['attachment_teardown_crashes']=[]
            for target in range(1,5):
                for when in ('before','after'):
                    def detach_child():
                        count=0
                        def crash(args,**kwargs):
                            nonlocal count
                            mutation=args[:3]==['ip','link','set']
                            if mutation:
                                count+=1
                                if count==target and when=='before':os.kill(os.getpid(),signal.SIGKILL)
                            value=execute(args,**kwargs)
                            if mutation and count==target and when=='after':os.kill(os.getpid(),signal.SIGKILL)
                            return value
                        guard(crash).detach_attachments()
                    process=multiprocessing.get_context('fork').Process(target=detach_child);process.start();process.join(30)
                    if process.is_alive():process.kill();process.join();raise RuntimeError('owned detach worker timeout')
                    assert process.exitcode==-signal.SIGKILL
                    guard().detach_attachments();assert invariant()==before
                    for role in ('a','b'):worker(role).operate('create')
                    ping();report['attachment_teardown_crashes'].append({'step':target,'when':when,'recovered':True})
            guard().detach_attachments()
            def infrastructure_child():
                def crash(args,**kwargs):
                    value=execute(args,**kwargs)
                    if args[:3]==['ip','link','delete']:os.kill(os.getpid(),signal.SIGKILL)
                    return value
                guard(crash).cleanup()
            process=multiprocessing.get_context('fork').Process(target=infrastructure_child);process.start();process.join(30)
            if process.is_alive():process.kill();process.join();raise RuntimeError('owned infrastructure worker timeout')
            assert process.exitcode==-signal.SIGKILL
            guard().cleanup();guard().verify_cleaned()
            actual={v['ifname']:v for v in links()}
            assert 'drsp-br' not in actual
            for role in ('a','b'):
                assert signature(actual['drsp-'+role])==proofs[role]['source'] and actual['drsp-'+role].get('master') is None
                assert signature(selected(role,'eth1'))==proofs[role]['peer']
            assert signature(actual['drsp-c'])==before['control'] and actual['drsp-c'].get('master')==before['control_master']
            assert signature(actual['drsp-ctrl'])==before['bridges']['drsp-ctrl']
            assert {role:signature(selected(role,'eth0')) for role in containers}==before['management']
            report['infrastructure_crash_after_bridge_delete_recovered']=True
            report['vd_veths_survive_infrastructure_cleanup']=True
            worker('c').operate('delete')
        else:
            for role in containers:worker(role).operate('delete')
        report['status']='passed' ;report['data_traffic']=True;report['management_and_control_preserved']=True
    except Exception as error:
        if owned_ns:
            try:
                report['host_links_at_failure']=links()
                report['vd_links_at_failure']={role:json.loads(vd(role,'ip','-j','-d','link','show')) for role in containers}
            except Exception as diagnostic_error:report['diagnostic_error']=str(diagnostic_error)
        report['status']='failed';report['error']=str(error)
        raise
    finally:
        try:
            # Only immutable, labelled fixture container IDs; explicit forced shutdown.
            for role,c in containers.items():
                current=json.loads(command(['docker','inspect',c['Id']]))[0]
                assert current['Id']==c['Id'] and current['Image']==c['Image'] and current['Config']['Labels']==c['Config']['Labels']
                if current['State']['Running']:command(['docker','kill','--signal','KILL',c['Id']])
                command(['docker','wait',c['Id']]);command(['docker','rm',c['Id']])
            if owned_ns:
                info=os.stat('/var/run/netns/'+namespace);assert (info.st_dev,info.st_ino)==owned_ns
                command(['ip','netns','delete',namespace])
            report['cleanup_verified']=not Path('/var/run/netns/'+namespace).exists() and all(not command(['docker','ps','-aq','--no-trunc','--filter','id='+c['Id']]).strip() for c in containers.values())
        except Exception as error:report['cleanup_error']=str(error);report['cleanup_verified']=False
        save();print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified')}))
    if not report.get('cleanup_verified'):raise RuntimeError('fixture cleanup incomplete')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--teardown-recovery',action='store_true');parser.add_argument('--generations',action='store_true');parser.add_argument('--image',required=True);args=parser.parse_args()
    if not args.execute:parser.error('explicit --execute required')
    run(args.image,teardown_recovery=args.teardown_recovery,generations=args.generations)
