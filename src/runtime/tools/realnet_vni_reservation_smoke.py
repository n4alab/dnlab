#!/usr/bin/env python3
"""Qualify per-edge VNI planning in an isolated two-lab, three-host star."""
import argparse
import copy
import json
import multiprocessing
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid

SOURCE=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(SOURCE/'multinode'),str(SOURCE/'runtime')]
from dnlab_multinode.models.topology import RealNet,RealNetLink
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import lab_cleanup,state as state_svc,realnet_vni
from dnlab_multinode.services.realnet import setup_bridges
from dnlab_multinode.services import realnet_cleanup
from dnlab_multinode.services.realnet_cleanup_host import OwnershipError,bridge_create_argv,link_identity
from dnlab_multinode.services.realnet_vni import Registry,reserve_realnets,snapshots

CORE=realnet_cleanup.PROGRAM.rsplit("if __name__=='__main__':main()",1)[0]
CLEANUP_PROGRAM=CORE+"\nworker=Worker(json.loads(sys.argv[1]),directory=sys.argv[2],attachment_directory=sys.argv[2]+'/attachments');print(json.dumps(getattr(worker,sys.argv[3])()))\n"


def run(daemon_crash=None):
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-vni-reservation-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8];roles=['master','worker1','worker2','a1','a2','b1','b2']
    names={role:'drsp-rnvr-'+token+'-'+role for role in roles};owned={};ports={}
    report={'scope':'isolated-per-edge-RealNet-VNI-reservations','status':'running','production_network_touched':False,
            'qualification':'native simulated data endpoints, three private host namespaces; no NOS/SSH service'}
    def save(name,value):(root/name).write_text(json.dumps(value,indent=2)+'\n')
    def command(argv,check=True):
        result=subprocess.run(argv,text=True,capture_output=True,timeout=45)
        if check and result.returncode:raise RuntimeError('fixture command failed: '+argv[0]+' '+result.stderr.strip())
        return result
    def verify(role):
        info=os.stat('/var/run/netns/'+names[role]);assert (info.st_dev,info.st_ino)==owned[role]
    def ns(role,*argv,check=True):
        verify(role);return command(['ip','netns','exec',names[role],*argv],check=check)
    def links(role):return json.loads(ns(role,'ip','-j','-d','link','show').stdout)
    def alias(role,name,value):ns(role,'ip','link','set',name,'alias',value)
    class NamespaceSSH:
        def __init__(self,host):self.host=host
        def run(self,text,check=True):
            argv=shlex.split(text)
            if len(argv)>3 and argv[:2]==['python3','-c'] and argv[2]==realnet_cleanup.PROGRAM:
                return ns(self.host,'python3','-c',CLEANUP_PROGRAM,argv[4],str(root/'cleanup-journals'/self.host),argv[3],check=check).stdout.strip()
            return ns(self.host,'/bin/sh','-c',text,check=check).stdout.strip()
        def run_no_check(self,text,timeout=30):
            result=ns(self.host,'/bin/sh','-c',text,check=False)
            return result.returncode,result.stdout,result.stderr
    clients={host:NamespaceSSH(host) for host in roles[:3]}
    underlay={'master':'198.18.0.1','worker1':'198.18.0.2','worker2':'198.18.0.3'}
    def topology(lab):
        return SimpleNamespace(name=lab,underlay_iface='under0',real_nets={'access':RealNet(name='access',ipv4='192.0.2.254/24')},
                               real_net_links=[RealNetLink(real_net='access',node='r1',iface='eth1',host='worker1'),
                                               RealNetLink(real_net='access',node='r2',iface='eth1',host='worker2')])
    def qualify_fixture(topo,state):
        # Qualify only resources this fixture has just created, keeping the
        # missing production ownership producer explicit in the report.
        observed=snapshots(clients,set(clients));proofs={}
        for host in clients:
            creator=uuid.uuid4().hex;value=realnet_cleanup.scope(topo.name,state.name,host)
            own_alias='dnlab-runtime:realnet:'+value+':'+creator
            stable_mac=bridge_create_argv(state.bridge,creator)[5]
            ns(host,'ip','link','set',state.bridge,'address',stable_mac)
            selected=[state.bridge,*state.vxlan_ifaces[host]]
            for name in selected:alias(host,name,own_alias)
            inventory={v['ifname']:v for v in links(host)}
            records={}
            for name in selected:
                link=inventory[name];kind=link['linkinfo']['info_kind']
                config={k:link['linkinfo']['info_data'][k] for k in ('id','local','remote','port','link')} if kind=='vxlan' else {}
                records[name]={'kind':kind,'identity':link_identity(link),'config':config}
            proofs[host]={'scope':value,'context':observed[host]['context'],'links':records,'router':None,'firewall':[]}
        state.resource_identities['realnet_cleanup_v1']=proofs
        state.router_container='';state.router_veth=''
    def attach(state,role,host,ip):
        name='d-'+role;verify(role)
        ns(host,'ip','link','add',name,'type','veth','peer','name','data0','netns',names[role])
        own_alias='drsp-realnet-vni-reservation:'+token+':'+role
        alias(host,name,own_alias);alias(role,'data0',own_alias)
        ns(host,'ip','link','set',name,'master',state.bridge);ns(host,'ip','link','set',name,'up')
        ns(role,'ip','addr','add',ip+'/24','dev','data0');ns(role,'ip','link','set','data0','up')
        ports[role]=(host,name,link_identity(next(v for v in links(host) if v['ifname']==name)))
    def ping(role,target,key,expected=True):
        result=ns(role,'ping','-n','-c','2','-W','1',target,check=False)
        save(key+'.json',{'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        assert (result.returncode==0)==expected,key
    def detach(role):
        host,name,identity=ports[role]
        assert link_identity(next(v for v in links(host) if v['ifname']==name))==identity
        ns(host,'ip','link','delete',name)
    def invariant(state):
        result={}
        for host in clients:
            inventory={v['ifname']:v for v in links(host)}
            result[host]={name:{'identity':link_identity(inventory[name]),'master':inventory[name].get('master'),
                               'kind':inventory[name]['linkinfo']['info_kind'],
                               'config':inventory[name]['linkinfo'].get('info_data') if inventory[name]['linkinfo']['info_kind']=='vxlan' else None}
                          for name in (state.bridge,*state.vxlan_ifaces[host])}
        return result
    try:
        for role,name in names.items():
            assert not Path('/var/run/netns',name).exists();command(['ip','netns','add',name])
            info=os.stat('/var/run/netns/'+name);owned[role]=(info.st_dev,info.st_ino)
            ns(role,'ip','link','set','lo','up')
        ns('master','ip','link','add','under0','type','bridge');ns('master','ip','link','set','under0','up')
        for host in ('worker1','worker2'):
            ns('master','ip','link','add','u-'+host,'type','veth','peer','name','under0','netns',names[host])
            ns('master','ip','link','set','u-'+host,'master','under0');ns('master','ip','link','set','u-'+host,'up')
            ns(host,'ip','link','set','under0','up')
        for host,ip in underlay.items():ns(host,'ip','addr','add',ip+'/24','dev','under0')
        registry=Registry(root/'vni');fabric=[]
        for lab in ('vni-lab-16','vni-lab-54'):
            topo=topology(lab)
            states=setup_bridges(topo,clients,underlay,vni_directory=registry.directory,
                                 checkpoint=lambda states:save('intent-'+lab+'.json',[s.__dict__ for s in states]))
            state=states[0];qualify_fixture(topo,state);fabric.append((topo,state))
        all_vnis=[vni for _,state in fabric for vni in state.vxlan_ids.values()]
        assert len(all_vnis)==len(set(all_vnis))==4
        save('fabric-state.json',[state.__dict__ for _,state in fabric])
        a,b=fabric[0][1],fabric[1][1]
        attach(a,'a1','worker1','192.0.2.1');attach(a,'a2','worker2','192.0.2.2')
        attach(b,'b1','worker1','192.0.2.11');attach(b,'b2','worker2','192.0.2.12')
        ping('a1','192.0.2.2','a-worker-to-worker');ping('b1','192.0.2.12','b-worker-to-worker')
        ping('a1','192.0.2.12','a-cannot-reach-b',expected=False)
        ping('b1','192.0.2.2','b-cannot-reach-a',expected=False)
        # Also overlap guest addresses across labs, proving fabric separation.
        ns('b2','ip','addr','add','192.0.2.2/24','dev','data0')
        ping('a1','192.0.2.2','a-with-overlapping-peer-ip')
        ping('b1','192.0.2.2','b-with-overlapping-peer-ip')
        for source,target in (('a1','a2'),('b1','b2')):
            neighbor=json.loads(ns(source,'ip','-j','neigh','show','to','192.0.2.2').stdout)
            expected=next(link['address'] for link in links(target) if link['ifname']=='data0')
            assert any(value.get('lladdr')==expected for value in neighbor)
            save('overlapping-ip-neighbor-'+source+'.json',{'neighbor':neighbor,'expected_mac':expected})
        baseline={topo.name:invariant(state) for topo,state in fabric};save('before-retry.json',baseline)
        before=(registry.directory/'registry.json').read_bytes()
        for topo,state in fabric:
            reserve_realnets(topo,clients,underlay,[state],directory=registry.directory)
        assert (registry.directory/'registry.json').read_bytes()==before
        after={topo.name:invariant(state) for topo,state in fabric};save('after-retry.json',after);assert after==baseline
        metadata=list(a.resource_identities['realnet_vni_v1'].values())
        try:registry.release(metadata,lambda:realnet_cleanup.verify_realnets_cleaned(fabric[0][0].name,clients,[a]))
        except OwnershipError:report['release_before_cleanup_refused']=True
        else:raise AssertionError('VNI released before authoritative cleanup')
        assert (registry.directory/'registry.json').read_bytes()==before
        detach('a1');detach('a2')
        for host,proof in a.resource_identities['realnet_cleanup_v1'].items():realnet_cleanup.invoke(clients[host],'cleanup',proof)
        if daemon_crash:
            lab=fabric[0][0].name
            teardown=DeploymentState(lab_name=lab,topology_file=str(root/(lab+'.yml')),
                                     teardown_requested=True,realnets=[copy.deepcopy(a)])
            state_svc.save_state(teardown,root)
            original_paths=realnet_vni.PATHS
            realnet_vni.PATHS=SimpleNamespace(realnet_vni_dir=str(registry.directory))
            try:
                def crash_finalizer():
                    original_release=realnet_vni.release_realnets
                    def release(*args,**kwargs):
                        if daemon_crash=='before':os.kill(os.getpid(),signal.SIGKILL)
                        original_release(*args,**kwargs)
                        os.kill(os.getpid(),signal.SIGKILL)
                    realnet_vni.release_realnets=release
                    lab_cleanup._finalize_requested_teardowns({lab:state_svc.load_state(lab,root)},root,None,clients=clients)
                process=multiprocessing.get_context('fork').Process(target=crash_finalizer)
                process.start();process.join(40)
                if process.is_alive():process.kill();process.join(5);raise RuntimeError('fixture finalizer timed out')
                assert process.exitcode==-signal.SIGKILL,process.exitcode
                assert state_svc.load_state(lab,root) is not None
                current=registry.read()['reservations']
                expected_phase='reserved' if daemon_crash=='before' else 'released'
                assert all(current[item['key']]['phase']==expected_phase for item in metadata)
                save('registry-after-finalizer-crash.json',registry.read())
                assert invariant(b)==baseline[fabric[1][0].name]
                status=lab_cleanup._finalize_requested_teardowns({lab:state_svc.load_state(lab,root)},root,None,clients=clients)
                assert status[lab].endswith('finalized') and state_svc.load_state(lab,root) is None,status
                assert all(registry.read()['reservations'][item['key']]['phase']=='released' for item in metadata)
                report['daemon_recovery']={'SIGKILL_relative_to_VNI_release':daemon_crash,'actual_SIGKILL':True,
                    'state_retained_after_crash':True,'VNI_phase_after_crash':expected_phase,
                    'fresh_finalizer_recovery':status[lab],'state_deleted_after_verified_release':True}
            finally:realnet_vni.PATHS=original_paths
        else:
            registry.release(metadata,lambda:realnet_cleanup.verify_realnets_cleaned(fabric[0][0].name,clients,[a]))
        assert invariant(b)==baseline[fabric[1][0].name]
        ping('b1','192.0.2.12','b-after-a-cleanup')
        save('registry-after-a-cleanup.json',registry.read())
        detach('b1');detach('b2')
        for host,proof in b.resource_identities['realnet_cleanup_v1'].items():realnet_cleanup.invoke(clients[host],'cleanup',proof)
        registry.release(list(b.resource_identities['realnet_vni_v1'].values()),
                         lambda:realnet_cleanup.verify_realnets_cleaned(fabric[1][0].name,clients,[b]))
        assert all(row['phase']=='released' for row in registry.read()['reservations'].values())
        report.update(status='passed',vnis=all_vnis,worker_to_worker_traffic=True,cross_lab_negative_probes=True,
                      retry_preserves_registry_and_kernel=True,other_lab_preserved_during_cleanup=True,
                      release_after_verified_remote_journals=True,production_ownership_producer_qualified=False)
    except BaseException as error:
        report.update(status='failed',error=str(error));raise
    finally:
        try:
            for role in reversed(list(owned)):
                verify(role);command(['ip','netns','delete',names[role]])
                assert not Path('/var/run/netns',names[role]).exists()
            report['cleanup_verified']=True
        except BaseException as error:
            report.update(cleanup_verified=False,cleanup_error=str(error));raise
        finally:
            save('report.json',report);print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified'),'error':report.get('error')}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--daemon-recovery',action='store_true',help='Run independent fixtures with real SIGKILL before/after VNI release')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'mutations_performed':False,'creates':'seven dedicated namespaces, two labs on three host namespaces, native data endpoints; no containers'}))
    elif os.geteuid()!=0:raise RuntimeError('fixture requires root')
    elif args.daemon_recovery:
        for moment in ('before','after'):run(moment)
    else:run()
