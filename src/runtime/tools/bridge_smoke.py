#!/usr/bin/env python3
"""Opt-in custom bridge primitive gate in five isolated network namespaces."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.bridge import BridgeLinux,BridgeManager
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.journal import Journal
from dnlab_runtime.vxlan import link_signature
from vxlan_smoke import NamespaceLinux,command,ip,ping,frame_probe


def run(*,crash_recovery=False,worker_image=None):
    root=Path(tempfile.mkdtemp(prefix='dnlab-custom-bridge-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8]
    names={key:'drsp-cbr-'+key+'-'+token for key in ('host','a1','a2','b1','b2')}
    created={};journal=None
    report={'scope':'custom-local-bridge-primitive-five-namespace-fixture','namespaces':names,
            'operation_api_qualified':False,'image_packaging_qualified':False,'nos_qualified':False}
    try:
        baseline=command(['ip','netns','list']).stdout
        for name in names.values():
            assert name not in baseline
            command(['ip','netns','add',name]);info=os.stat('/var/run/netns/'+name)
            created[name]=(info.st_dev,info.st_ino);ip(name,'link','set','lo','up')
        identities={side:BridgeIdentity('bridge-fixture-'+token+'-'+side,'l0') for side in ('a','b')}
        for side in ('a','b'):
            for index in (1,2):
                source='rt-'+token+side+str(index)
                ip(names['host'],'link','add',source,'mtu','1450','type','veth','peer','name','eth0','netns',names[side+str(index)])
                ip(names['host'],'link','set','dev',source,'alias','dnlab-runtime:fixture-'+token+'-'+side)
                ip(names['host'],'link','set',source,'up')
                ip(names[side+str(index)],'link','set','eth0','mtu','1450','up')
                ip(names[side+str(index)],'address','add',f'198.19.204.{index}/24','dev','eth0')
        executor=NamespaceLinux(names['host']);linux=BridgeLinux(executor)
        sources={side:[value for value in linux.links() if value['ifname'] in ('rt-'+token+side+'1','rt-'+token+side+'2')] for side in ('a','b')}
        left,right=[value['ifname'] for value in sources['a']]
        executor.run(['tc','qdisc','add','dev',left,'clsact'])
        executor.run(['tc','filter','add','dev',left,'ingress','pref','12345','protocol','arp','flower','action','pass'])
        foreign_before=linux.filters(left)
        foreign_rule=['-A','FORWARD','-i',identities['a'].kernel_name,'-m','comment','--comment','fixture-foreign-'+token,'-j','ACCEPT']
        executor.run(['iptables','-I','FORWARD','1',*foreign_rule[2:]])
        journal=Journal(root/'state');manager=BridgeManager(journal,linux)
        for side in ('a','b'):manager.create(identities[side],sources=sources[side],mtu=1450)
        snapshot={side:manager.row(identities[side].digest)['payload'] for side in ('a','b')}
        report['icmp']={side:ping(names[side+'1'],'198.19.204.2') for side in ('a','b')}
        report['frames']={}
        for source,target in [('a1','a2'),('a2','a1'),('b1','b2')]:
            for protocol,destination,ethertype in [('lldp','0180c200000e','88cc'),('lacp','0180c2000002','8809')]:
                report['frames'][source+'-'+protocol]=frame_probe(names[source],names[target],destination,ethertype)
        count=len(executor.commands)
        manager.create(identities['a'],sources=sources['a'],mtu=1450)
        assert all('-j' in argv or argv[:2]==['iptables','-S'] for argv in executor.commands[count:])
        executor.run(['tc','filter','add','dev',right,'egress','pref','12346','protocol','arp','flower','action','pass'])
        egress_before=linux.filters(right,'egress')
        manager.delete(identities['a'])
        assert linux.filters(left)==foreign_before and linux.filters(right,'egress')==egress_before
        assert foreign_rule in linux.forward_rules()
        report['a_deleted']=ping(names['a1'],'198.19.204.2',expected=False)
        report['b_preserved']=ping(names['b1'],'198.19.204.2')
        manager.verify(identities['b'],snapshot['b'])
        executor.inject_lost_redirect=True
        try:manager.create(identities['a'],sources=sources['a'],mtu=1450)
        except RuntimeError as error:assert str(error)=='injected lost source-redirect response'
        else:raise RuntimeError('lost-response injection did not fire')
        assert manager.row(identities['a'].digest)['phase']=='cleaned'
        assert linux.filters(left)==foreign_before and linux.filters(right,'egress')==egress_before
        manager.verify(identities['b'],snapshot['b'])
        manager.create(identities['a'],sources=sources['a'],mtu=1450)
        report['recreated']=ping(names['a1'],'198.19.204.2')
        for side in ('a','b'):
            manager.delete(identities[side])
            assert manager.row(identities[side].digest)['phase']=='cleaned'
            observed=[link_signature(value) for value in linux.links() if value['ifname'] in {s['ifname'] for s in sources[side]}]
            assert sorted(observed,key=lambda v:v['ifname'])==sorted([link_signature(s) for s in sources[side]],key=lambda v:v['ifname'])
        assert linux.filters(left)==foreign_before and linux.filters(right,'egress')==egress_before
        assert foreign_rule in linux.forward_rules()
        report['checks']=['two same-subnet labs remain isolated','ICMP and raw LLDP/LACP frames','active retry has no kernel mutation',
                          'delete A preserves B','foreign ingress/egress qdiscs and firewall rule preserved',
                          'lost TC response compensated, B unchanged','recreate restores traffic','source veth identities unchanged','journals cleaned']
        from bridge_vxlan_reservation_probe import probe as reservation_probe
        reservation_probe(report,manager,executor,identities,sources,root=root,names=names,worker_image=worker_image)
        if crash_recovery:
            from bridge_crash_probe import probe
            probe(root,report,names,manager,identities,sources,worker_image=worker_image)
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        if journal:journal.close()
        try:
            for name,identity in reversed(list(created.items())):
                info=os.stat('/var/run/netns/'+name);assert (info.st_dev,info.st_ino)==identity
                command(['ip','netns','delete',name])
            assert all(not os.path.exists('/var/run/netns/'+name) for name in created)
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps({'report':str(root/'report.json'),'status':report.get('status'),'error':report.get('error'),'cleanup_verified':report.get('cleanup_verified')}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--crash-recovery',action='store_true');parser.add_argument('--worker-image');args=parser.parse_args()
    if args.worker_image and not args.crash_recovery:parser.error('--worker-image requires --crash-recovery')
    if not args.execute:
        print(json.dumps({'mutations_performed':False,'creates':'five drsp namespaces, two journalled local bridges and fixture peer veth','host_network_changed':False}));return
    if os.geteuid()!=0:raise RuntimeError('live bridge gate requires root')
    run(crash_recovery=args.crash_recovery,worker_image=args.worker_image)


if __name__=='__main__':main()
