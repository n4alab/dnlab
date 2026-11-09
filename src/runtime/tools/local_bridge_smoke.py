#!/usr/bin/env python3
"""Opt-in legacy bridge/TC gate; all networking stays in five fixture namespaces."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'multinode'))
sys.path.insert(0,str(ROOT/'runtime'))
from dnlab_multinode.models.state import RuntimeLinkState
from dnlab_multinode.services import runtime_links
from dnlab_multinode.services.bridge_guard import BridgeOwnershipError
from dnlab_multinode.utils import naming
from vxlan_smoke import command,ip,ping,frame_probe


class NamespaceClient:
    def __init__(self,name):self.name,self.commands=name,[]
    def run(self,text,check=True):
        self.commands.append(text)
        result=command(['ip','netns','exec',self.name,'/bin/sh','-c',text],check=check)
        return result.stdout.strip()
    def mutations_since(self,count):
        return [value for value in self.commands[count:] if not value.startswith(('ip -j','tc -j','python3 -c'))]


def run():
    root=Path(tempfile.mkdtemp(prefix='dnlab-local-bridge-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8]
    names={key:'drsp-btc-'+key+'-'+token for key in ('host','a1','a2','b1','b2')}
    created={}
    report={'scope':'single-host-isolated-namespace-legacy-local-bridge-and-TC',
            'custom_bridge_api_qualified':False,'nos_qualified':False,'namespaces':names,'checks':[]}
    client=NamespaceClient(names['host'])
    links={}
    try:
        baseline=command(['ip','netns','list']).stdout
        for name in names.values():
            assert name not in baseline
            command(['ip','netns','add',name])
            info=os.stat('/var/run/netns/'+name);created[name]=(info.st_dev,info.st_ino)
            ip(name,'link','set','lo','up')
        for side in ('a','b'):
            lab='bridge-tc-'+token+'-'+side
            ports=[naming.runtime_host_endpoint(lab,'R'+str(index),'eth1','l0') for index in (1,2)]
            links[side]=RuntimeLinkState(id='l0',lab_name=lab,link_type='same_host',host_a='master',host_b='master',
                endpoint_a={'node':'R1','iface':'eth1'},endpoint_b={'node':'R2','iface':'eth1'},
                host_endpoint_a=ports[0],host_endpoint_b=ports[1],bridge_name=naming.runtime_bridge_name(lab,'l0'))
            for index,port in enumerate(ports,1):
                guest=names[side+str(index)]
                ip(names['host'],'link','add',port,'type','veth','peer','name','eth0','netns',guest)
                ip(names['host'],'link','set','dev',port,'alias','dnlab-runtime:fixture-'+lab)
                ip(names['host'],'link','set',port,'up')
                ip(guest,'link','set','lo','up');ip(guest,'link','set','eth0','up')
                ip(guest,'address','add',f'198.19.203.{index}/24','dev','eth0')
        left=links['a'].host_endpoint_a;right=links['a'].host_endpoint_b
        # A preexisting, unrelated ARP filter does not intercept LLDP/LACP.
        client.run(f'tc qdisc add dev {left} clsact')
        client.run(f'tc filter add dev {left} ingress pref 12345 protocol arp flower action pass')
        foreign_before=json.loads(client.run(f'tc -j filter show dev {left} ingress'))
        report['foreign_before']=foreign_before
        for link in links.values():runtime_links.create_link(link,{'master':client},running_nodes={'R1','R2'})
        assert links['a'].bridge_name!=links['b'].bridge_name
        report['icmp']={side:ping(names[side+'1'],'198.19.203.2') for side in ('a','b')}
        report['frames']={}
        for source,target in [('a1','a2'),('a2','a1'),('b1','b2')]:
            for protocol,dest,ether in [('lldp','0180c200000e','88cc'),('lacp','0180c2000002','8809')]:
                report['frames'][source+'-'+protocol]=frame_probe(names[source],names[target],dest,ether)
        before=copy.deepcopy(links['a'].resource_identities)
        count=len(client.commands)
        runtime_links.create_link(links['a'],{'master':client},running_nodes={'R1','R2'})
        assert links['a'].resource_identities==before
        assert not any(value.startswith(('tc filter','tc qdisc')) for value in client.mutations_since(count))
        # A newly created clsact can become shared through an egress filter.
        client.run(f'tc filter add dev {right} egress pref 12346 protocol arp flower action pass')
        egress_before=json.loads(client.run(f'tc -j filter show dev {right} egress'))
        runtime_links.delete_link(links['a'],{'master':client})
        assert json.loads(client.run(f'tc -j filter show dev {left} ingress'))==foreign_before
        assert json.loads(client.run(f'tc -j filter show dev {right} egress'))==egress_before
        assert all(any(q.get('kind')=='clsact' for q in json.loads(client.run(f'tc -j qdisc show dev {port}'))) for port in (left,right))
        report['a_deleted_traffic']=ping(names['a1'],'198.19.203.2',expected=False)
        report['b_preserved_traffic']=ping(names['b1'],'198.19.203.2')
        client.run(f'tc filter add dev {left} ingress pref 49140 protocol ip flower action pass')
        count=len(client.commands)
        try:runtime_links.create_link(links['a'],{'master':client},running_nodes={'R1','R2'})
        except BridgeOwnershipError as error:
            assert 'priority' in str(error)
        else:raise RuntimeError('foreign priority was accepted')
        assert not client.mutations_since(count)
        client.run(f'tc filter del dev {left} ingress pref 49140 protocol ip')
        runtime_links.create_link(links['a'],{'master':client},running_nodes={'R1','R2'})
        report['recreated_traffic']=ping(names['a1'],'198.19.203.2')
        for link in links.values():runtime_links.delete_link(link,{'master':client})
        report['checks']=['overlapping guest subnet isolated by distinct lab bridges','IPv4 and LLDP/LACP frames',
                          'retry without TC rewrite','foreign ingress/preexisting clsact preserved',
                          'foreign egress/newly shared clsact preserved','teardown A preserves B traffic',
                          'foreign reserved priority rejected before mutation','recreate restores traffic']
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        try:
            for name,identity in reversed(list(created.items())):
                info=os.stat('/var/run/netns/'+name)
                assert (info.st_dev,info.st_ino)==identity
                command(['ip','netns','delete',name])
            assert all(not os.path.exists('/var/run/netns/'+name) for name in created)
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            report['resource_state']={side:link.resource_identities for side,link in links.items()}
            (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            (root/'commands.json').write_text(json.dumps(client.commands,indent=2)+'\n')
            print(json.dumps({'report':str(root/'report.json'),'status':report.get('status'),
                              'cleanup_verified':report.get('cleanup_verified'),'error':report.get('error')}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if not args.execute:
        print(json.dumps({'mutations_performed':False,'creates':'five drsp fixture namespaces, two lab bridges, dedicated guest veth and TC rules','host_network_changed':False}));return
    if os.geteuid()!=0:raise RuntimeError('live probe requires root')
    run()


if __name__=='__main__':main()
