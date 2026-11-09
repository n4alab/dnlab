import copy
import json
import os
import shlex

import pytest

from dnlab_multinode.services.realnet_bootstrap_host import Bootstrap
from dnlab_multinode.services.realnet_cleanup_host import OwnershipError
from tests.test_realnet_cleanup import CONTEXT,fixture_plan


def request_and_kernel():
    infrastructure,links=fixture_plan();infrastructure['links'].pop('vh-test');infrastructure['router']=None
    links.pop('vh-test')
    request={'infrastructure':infrastructure,'bridge':'br-test','endpoint':'vh-test','container':'router-test',
             'image':'fixture-image','network':'fixture-network','environment':{'REALNET_IPV4':'192.0.2.1/24',
             'NAT_ENABLED':'true','BGP_ENABLED':'false','BGP_ROUTER_ID':''},'ip':None}
    return request,Kernel(request,links)


class Kernel:
    def __init__(self,request,links):
        self.request=request;self.links=copy.deepcopy(links);self.container=None;self.peer={}
        self.links['eth1']={'ifname':'eth1','ifindex':30,'address':'00:11:22:33:44:55','ifalias':'host-infrastructure'}
        self.mutations=[];self.fail_after=None;self.initial_peer=None
        self.rules=copy.deepcopy(request['infrastructure']['firewall'])
    def run(self,args,*,pass_fds=()):
        if args==['iptables-save','-t','filter']:return '\n'.join(shlex.join(['-A',*rule]) for rule in self.rules)
        if args[:3]==['docker','image','inspect']:return json.dumps([{'Id':'sha256:'+'d'*64,'Config':{'Entrypoint':['fixture'],'Cmd':None}}])
        if args[:3]==['docker','network','inspect']:return json.dumps([{'Id':'b'*64}])
        if args[:3]==['docker','ps','-aq']:return self.container['Id'] if self.container else ''
        if args[:2]==['docker','inspect']:return json.dumps([self.container])
        if args==['ip','-j','-d','link','show']:return json.dumps(list(self.links.values()))
        guest=args[0]=='nsenter'
        command=args[3:] if guest else args
        if guest:
            assert pass_fds and args[1]=='--net=/proc/self/fd/'+str(pass_fds[0])
        if command==['ip','-j','-d','link','show']:return json.dumps(list(self.peer.values()))
        if args[:2]==['docker','run']:
            labels={entry.split('=',1)[0]:entry.split('=',1)[1] for index,entry in enumerate(args) if index and args[index-1]=='--label'}
            env=[entry for index,entry in enumerate(args) if index and args[index-1]=='-e']
            self.container={'Id':'c'*64,'Name':'/router-test','Image':'sha256:'+'d'*64,
                'Config':{'Labels':labels,'Env':env,'Entrypoint':['fixture'],'Cmd':None},
                'HostConfig':{'Privileged':True,'CapAdd':['CAP_NET_ADMIN']},
                'State':{'Running':True,'Pid':os.getpid()},
                'NetworkSettings':{'Networks':{'fixture-network':{'NetworkID':'b'*64,'IPAddress':'198.18.0.2'}}}}
            if self.initial_peer:self.peer=copy.deepcopy(self.initial_peer)
        elif command[:3]==['ip','link','add']:
            assert not guest and command[-2]=='netns' and pass_fds
            assert command[-1]=='/proc/self/fd/'+str(pass_fds[0])
            name=command[3];peer=command[command.index('peer')+2]
            assert name not in self.links and peer not in self.peer
            host_mac=command[5];peer_mac=command[command.index('peer')+4]
            self.links[name]={'ifname':name,'ifindex':40,'link_index':41,'address':host_mac,'linkinfo':{'info_kind':'veth'},'flags':[]}
            self.peer[peer]={'ifname':peer,'ifindex':41,'link_index':40,'address':peer_mac,'linkinfo':{'info_kind':'veth'},'flags':[]}
        elif command[:4]==['ip','link','set','dev']:
            table=self.peer if guest else self.links;value=table[command[4]]
            if command[5]=='alias':value['ifalias']=command[6]
            elif command[5]=='master':value['master']=command[6]
            elif command[5]=='up':value['flags']=['UP']
            else:raise AssertionError(command)
        else:raise AssertionError(args)
        self.mutations.append(args)
        if self.fail_after==len(self.mutations):raise RuntimeError('crash after mutation before ACK')
        return 'c'*64 if args[:2]==['docker','run'] else ''


def worker(tmp_path):
    request,kernel=request_and_kernel()
    return Bootstrap(request,run=kernel.run,host_context=lambda:CONTEXT,directory=tmp_path/'bootstrap'),kernel


def test_peer_is_created_directly_in_pinned_namespace_and_host_eth1_is_untouched(tmp_path):
    bootstrap,kernel=worker(tmp_path);foreign=copy.deepcopy(kernel.links['eth1'])
    result=bootstrap.deploy()
    assert result['phase']=='active' and result['host_link']['identity']['link_index']==41
    assert kernel.links['eth1']==foreign
    adds=[args for args in kernel.mutations if args[:3]==['ip','link','add']]
    assert len(adds)==1 and adds[0][-2]=='netns' and adds[0][-1].startswith('/proc/self/fd/')
    assert not any('netns' in args and args[:3]==['ip','link','set'] for args in kernel.mutations)
    count=len(kernel.mutations);assert bootstrap.deploy()['container_id']==result['container_id']
    assert len(kernel.mutations)==count


@pytest.mark.parametrize('after',range(1,8))
def test_bootstrap_recovery_after_each_allocation_or_attach_mutation(tmp_path,after):
    bootstrap,kernel=worker(tmp_path);foreign=copy.deepcopy(kernel.links['eth1']);kernel.fail_after=after
    with pytest.raises(RuntimeError,match='crash'):bootstrap.deploy()
    record=json.loads((bootstrap.directory/(bootstrap.infrastructure['scope']+'.json')).read_text())
    assert record['phase']=='applying' and 'intent' in record['steps'].values()
    kernel.fail_after=None
    recovered=Bootstrap(bootstrap.request,run=kernel.run,host_context=lambda:CONTEXT,directory=bootstrap.directory)
    assert recovered.deploy()['phase']=='active' and kernel.links['eth1']==foreign


@pytest.mark.parametrize('resource',['host_endpoint','foreign_helper','foreign_bridge_port','bridge_changed'])
def test_preflight_conflicts_prevent_all_allocation(tmp_path,resource):
    bootstrap,kernel=worker(tmp_path)
    if resource=='host_endpoint':kernel.links['vh-test']={**kernel.links['eth1'],'ifname':'vh-test'}
    if resource=='foreign_helper':kernel.container={'Id':'f'*64,'Name':'/router-test'}
    if resource=='foreign_bridge_port':kernel.links['eth1']['master']='br-test'
    if resource=='bridge_changed':kernel.links['br-test']['ifindex']=99
    with pytest.raises(OwnershipError):bootstrap.deploy()
    assert not kernel.mutations and not bootstrap.directory.exists()


def test_foreign_guest_eth1_prevents_veth_allocation(tmp_path):
    bootstrap,kernel=worker(tmp_path)
    kernel.initial_peer={'eth1':{'ifname':'eth1','ifindex':20,'address':'00:00:00:00:00:ff'}}
    with pytest.raises(OwnershipError,match='foreign helper LAN'):bootstrap.deploy()
    assert not any(args[:3]==['ip','link','add'] for args in kernel.mutations)


def test_active_retry_refuses_replaced_peer_without_mutation(tmp_path):
    bootstrap,kernel=worker(tmp_path);bootstrap.deploy();count=len(kernel.mutations)
    kernel.peer['eth1']['ifindex']=99
    with pytest.raises(OwnershipError):bootstrap.deploy()
    assert len(kernel.mutations)==count
