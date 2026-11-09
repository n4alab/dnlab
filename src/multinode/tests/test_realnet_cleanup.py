import copy
import json
import shlex

import pytest

from dnlab_multinode.models.state import RealNetState
from dnlab_multinode.services import realnet_cleanup as coordinator
from dnlab_multinode.services.realnet_cleanup_host import OwnershipError,Worker,link_identity

CONTEXT={'boot_id':'test-boot','device':1,'inode':2}


def fixture_plan(host='master'):
    scope=coordinator.scope('lab','access',host)
    alias='dnlab-runtime:realnet:'+scope+':'+'a'*32
    kinds=[('br-test','bridge'),('vx-test','vxlan')]
    if host=='master':kinds.append(('vh-test','veth'))
    links={name:{'ifname':name,'ifindex':index,'address':'02:00:00:00:00:'+str(index),
                 'ifalias':alias,'link_index':None,'linkinfo':{'info_kind':kind,'info_data':{}},
                 **({'master':'br-test'} if kind!='bridge' else {})}
           for index,(name,kind) in enumerate(kinds,10)}
    labels={'org.dnlab.realnet.scope':scope,'org.dnlab.realnet.creator':'a'*32}
    router={'id':'c'*64,'name':'router-test','image':'sha256:'+'d'*64,'labels':labels} if host=='master' else None
    plan={'scope':scope,'context':CONTEXT,'links':{name:{'identity':link_identity(value),'kind':value['linkinfo']['info_kind'],'config':{}} for name,value in links.items()},
          'router':router,'firewall':[['FORWARD',direction,'br-test','-m','comment','--comment',alias,'-j','ACCEPT'] for direction in ('-i','-o')]}
    return plan,links


class Kernel:
    def __init__(self,plan,links):
        self.plan=plan;self.links=copy.deepcopy(links);self.rules=copy.deepcopy(plan['firewall'])
        self.router=copy.deepcopy(plan['router']);self.running=True;self.mutations=[];self.fail_after=None
    def run(self,args):
        if args==['ip','-j','-d','link','show']:return json.dumps(list(self.links.values()))
        if args[:3]==['docker','ps','-aq']:return self.router['id'] if self.router else ''
        if args[:2]==['docker','inspect']:
            router=self.router
            return json.dumps([{'Id':router['id'],'Name':'/'+router['name'],'Image':router['image'],'Config':{'Labels':router['labels']},'State':{'Running':self.running}}])
        if args==['iptables-save','-t','filter']:return '\n'.join(shlex.join(['-A',*rule]) for rule in self.rules)
        if args[:4]==['ip','link','delete','dev']:del self.links[args[4]]
        elif args[:2]==['docker','kill']:self.running=False
        elif args[:2]==['docker','wait']:return '137'
        elif args[:2]==['docker','rm']:self.router=None
        elif args[:4]==['iptables','-w','5','-D']:self.rules.remove(args[4:])
        else:raise AssertionError(args)
        self.mutations.append(args)
        if self.fail_after==len(self.mutations):raise RuntimeError('crash after mutation before ACK')
        return ''


def make_worker(tmp_path,host='master'):
    plan,links=fixture_plan(host);kernel=Kernel(plan,links)
    worker=Worker(plan,run=kernel.run,host_context=lambda:CONTEXT,directory=tmp_path/'journal',attachment_directory=tmp_path/'attachments')
    return worker,kernel


def test_cleanup_preserves_foreign_rules_and_is_idempotent(tmp_path):
    worker,kernel=make_worker(tmp_path)
    foreign=['FORWARD','-i','br-test','-j','ACCEPT'];kernel.rules.append(foreign)
    assert worker.preflight()['status']=='verified' and not kernel.mutations
    assert worker.cleanup()['status']=='cleaned'
    assert kernel.rules==[foreign] and not kernel.links and kernel.router is None
    count=len(kernel.mutations);worker.cleanup();assert len(kernel.mutations)==count
    record=json.loads((worker.directory/(worker.plan['scope']+'.json')).read_text())
    assert record['phase']=='cleaned' and set(record['steps'].values())=={'done'}
    assert all(args[:3]!=['docker','rm','-f'] for args in kernel.mutations)


@pytest.mark.parametrize('change',['alias','address','ifindex','kind','context','foreign_member','router_id','router_labels','duplicate_rule','rule_changed'])
def test_preflight_refuses_ownership_changes_without_mutations(tmp_path,change):
    worker,kernel=make_worker(tmp_path)
    if change=='alias':kernel.links['br-test']['ifalias']='foreign'
    if change=='address':kernel.links['br-test']['address']='00:00:00:00:00:00'
    if change=='ifindex':kernel.links['br-test']['ifindex']=99
    if change=='kind':kernel.links['vx-test']['linkinfo']['info_kind']='dummy'
    if change=='context':worker.host_context=lambda:{**CONTEXT,'inode':3}
    if change=='foreign_member':kernel.links['foreign']={'ifname':'foreign','master':'br-test'}
    if change=='router_id':kernel.router['id']='f'*64
    if change=='router_labels':kernel.router['labels']={}
    if change=='duplicate_rule':kernel.rules.append(kernel.rules[0])
    if change=='rule_changed':kernel.rules[0][-1]='DROP'
    with pytest.raises(OwnershipError):worker.preflight()
    assert not kernel.mutations and not worker.directory.exists()


@pytest.mark.parametrize('after',range(1,8))
def test_crash_after_each_mutation_recovers_from_persistent_intent(tmp_path,after):
    worker,kernel=make_worker(tmp_path);kernel.fail_after=after
    with pytest.raises(RuntimeError,match='crash'):worker.cleanup()
    path=worker.directory/(worker.plan['scope']+'.json')
    record=json.loads(path.read_text());assert record['phase']=='cleanup_pending' and 'intent' in record['steps'].values()
    kernel.fail_after=None
    recovered=Worker(worker.plan,run=kernel.run,host_context=lambda:CONTEXT,directory=worker.directory,attachment_directory=worker.attachment_directory)
    assert recovered.cleanup()['status']=='cleaned'
    assert not kernel.links and not kernel.router and not kernel.rules


def test_retry_refuses_same_name_replacement_after_partial_cleanup(tmp_path):
    worker,kernel=make_worker(tmp_path);kernel.fail_after=1
    with pytest.raises(RuntimeError):worker.cleanup()
    _,links=fixture_plan();kernel.links['vh-test']={**links['vh-test'],'ifindex':88}
    kernel.fail_after=None;count=len(kernel.mutations)
    with pytest.raises(OwnershipError):worker.cleanup()
    assert len(kernel.mutations)==count


def state_and_clients():
    state=RealNetState(name='access',bridge='br-test',vxlan_id=42,hosts=['master','worker1'],router_container='router-test',router_veth='vh-test',vxlan_ifaces={'master':['vx-test'],'worker1':['vx-test']})
    state.resource_identities['realnet_cleanup_v1']={host:fixture_plan(host)[0] for host in state.hosts}
    class Client:
        def __init__(self,name):self.name=name
    return state,{host:Client(host) for host in state.hosts}


def test_all_hosts_preflight_before_first_cleanup(monkeypatch):
    state,clients=state_and_clients();calls=[];saved=[]
    def invoke(client,action,plan):calls.append((client.name,action));return {'status':'cleaned' if action=='cleanup' else 'verified'}
    monkeypatch.setattr(coordinator,'invoke',invoke)
    coordinator.destroy_realnets('lab',clients,[state],checkpoint=lambda:saved.append(copy.deepcopy(state.resource_identities)))
    assert calls==[('master','preflight'),('worker1','preflight'),('master','detach_attachments'),('worker1','detach_attachments'),('master','cleanup'),('worker1','cleanup')]
    assert saved[0]['realnet_attachment_teardown']['phase']=='cleanup_pending'
    assert saved[-1]['realnet_cleanup_operation']['phase']=='cleaned'


@pytest.mark.parametrize('missing',[True,False])
def test_unavailable_host_prevents_every_cleanup(monkeypatch,missing):
    state,clients=state_and_clients();calls=[]
    if missing:del clients['worker1']
    def invoke(client,action,plan):
        calls.append((client.name,action))
        if client.name=='worker1':raise OwnershipError('host unavailable')
    monkeypatch.setattr(coordinator,'invoke',invoke)
    with pytest.raises(OwnershipError):coordinator.destroy_realnets('lab',clients,[state])
    assert all(action=='preflight' for _,action in calls)
    assert 'realnet_cleanup_operation' not in state.resource_identities


def test_failure_after_preflight_retains_pending_state(monkeypatch):
    state,clients=state_and_clients();saved=[]
    def invoke(client,action,plan):
        if action=='cleanup' and client.name=='worker1':raise OwnershipError('worker lost after preflight')
    monkeypatch.setattr(coordinator,'invoke',invoke)
    with pytest.raises(OwnershipError):coordinator.destroy_realnets('lab',clients,[state],checkpoint=lambda:saved.append(copy.deepcopy(state.resource_identities)))
    operation=saved[-1]['realnet_cleanup_operation']
    assert operation['phase']=='cleanup_pending' and operation['hosts']=={'master':'cleaned','worker1':'cleanup_pending'}


def test_bridge_creation_sets_stable_local_unicast_mac_in_add_command():
    from dnlab_multinode.services.realnet_cleanup_host import bridge_create_argv
    command=bridge_create_argv('br-test','a'*32)
    assert command[:5]==['ip','link','add','br-test','address']
    assert command[6:]==['type','bridge']
    assert int(command[5].split(':')[0],16)&3==2
    assert command==bridge_create_argv('br-test','a'*32)
    assert command[5]!=bridge_create_argv('br-test','b'*32)[5]


@pytest.mark.parametrize('name,creator',[('br;touch','a'*32),('a'*16,'a'*32),('br-test',''),('br-test','z'*32)])
def test_bridge_creation_refuses_invalid_identity(name,creator):
    from dnlab_multinode.services.realnet_cleanup_host import bridge_create_argv
    with pytest.raises(OwnershipError):bridge_create_argv(name,creator)


def test_finalization_requires_complete_durable_journal_and_absence(tmp_path):
    worker,kernel=make_worker(tmp_path)
    with pytest.raises(OwnershipError,match='missing'):worker.verify_cleaned()
    assert not worker.directory.exists() and not kernel.mutations
    worker.cleanup();before=list(kernel.mutations)
    assert worker.verify_cleaned()['status']=='cleaned'
    assert kernel.mutations==before
    path=worker.directory/(worker.plan['scope']+'.json')
    record=json.loads(path.read_text());record['steps']['router']='intent'
    path.write_text(json.dumps(record))
    with pytest.raises(OwnershipError,match='incomplete'):worker.verify_cleaned()
    assert kernel.mutations==before


def test_finalization_refuses_owned_firewall_remaining_even_with_cleaned_marker(tmp_path):
    worker,kernel=make_worker(tmp_path);worker.cleanup()
    kernel.rules.append(copy.deepcopy(worker.plan['firewall'][0]))
    with pytest.raises(OwnershipError,match='incomplete'):worker.verify_cleaned()


def test_finalization_refuses_foreign_replacement_and_changed_journal_proof(tmp_path):
    worker,kernel=make_worker(tmp_path);worker.cleanup()
    _,links=fixture_plan();kernel.links['br-test']={**links['br-test'],'ifalias':'foreign'}
    with pytest.raises(OwnershipError,match='ownership'):worker.verify_cleaned()
    kernel.links.clear()
    path=worker.directory/(worker.plan['scope']+'.json');record=json.loads(path.read_text())
    record['proof']['context']['inode']=99;path.write_text(json.dumps(record))
    with pytest.raises(OwnershipError,match='proof differs'):worker.verify_cleaned()
