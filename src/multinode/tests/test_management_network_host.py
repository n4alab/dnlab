"""Stateful Docker/plugin and real journal tests; no host operations."""
import copy

import pytest

from dnlab_multinode.services.management_host import Worker, ManagementError
from dnlab_multinode.services.management_network_host import NetworkGuard, NetworkError
from tests.test_management_host import Host, plan, SCOPE


def expected():
    return dict(driver='dnlab-vrf',ipam_driver='dnlab-vrf',network='mgmt-alpha',bridge='bm1',vrf='vrfa',lab='breakout-alpha',
        ipv4_subnet='10.1.0.0/24',ipv4_gateway='10.1.0.1',ipv6_subnet='2001:db8:1::/64',ipv6_gateway='2001:db8:1::254',
        host_index=0,host_count=1,reserved=['10.1.0.1','10.1.0.254'],labels={'io.dnlab.managed':'mgmt-vrf','io.dnlab.lab':'breakout-alpha'})


class Docker:
    def __init__(self):
        self.networks={};self.next=1;self.calls=[];self.after=None;self.failure=None
        self.plugin=dict(version=2,networks={},endpoints={},pools={})
    def inspect(self,identity):
        if self.failure:raise NetworkError(self.failure)
        found=[v for v in self.networks.values() if identity in (v['Name'],v['Id'])]
        if len(found)>1:raise NetworkError('ambiguous network')
        return copy.deepcopy(found[0]) if found else None
    def create(self,config):
        self.calls.append(('create',copy.deepcopy(config)))
        identity=f'{self.next:064x}';self.next+=1
        value=copy.deepcopy(config);value.update(Id=identity,Scope='local',Containers={},ConfigOnly=False)
        value.pop('CheckDuplicate');self.networks[identity]=value
        pools=value['IPAM']['Config'];options=value['Options']
        self.plugin['networks'][identity]=dict(bridge=options['dnlab.bridge'],vrf=options['dnlab.vrf'],lab=options['dnlab.lab'],
            ipv4_subnet=pools[0]['Subnet'],ipv4_gateway=pools[0]['Gateway'],ipv6_subnet=pools[1]['Subnet'] if len(pools)>1 else '',ipv6_gateway=pools[1]['Gateway'] if len(pools)>1 else '')
        for i,pool in enumerate(pools):
            self.plugin['pools'][identity+str(i)] = dict(tenant=config['Name'],pool=pool['Subnet'],v6=i==1,host_index=int(config['IPAM']['Options']['dnlab.host-index']),host_count=int(config['IPAM']['Options']['dnlab.host-count']),reserved=sorted(v for v in config['IPAM']['Options']['dnlab.reserved'].split(',') if bool(':' in v)==(i==1)),allocated=[])
        if self.after=='create':self.after=None;raise RuntimeError('lost create response')
        return {'Id':identity,'Warning':''}
    def delete(self,identity):
        self.calls.append(('delete',identity));self.networks.pop(identity,None);self.plugin['networks'].pop(identity,None)
        self.plugin['pools']={k:v for k,v in self.plugin['pools'].items() if not k.startswith(identity)}
        if self.after=='delete':self.after=None;raise RuntimeError('lost delete response')
    def remove_external(self,identity):
        self.networks.pop(identity,None);self.plugin['networks'].pop(identity,None)
        self.plugin['pools']={k:v for k,v in self.plugin['pools'].items() if not k.startswith(identity)}


@pytest.fixture
def fixture(tmp_path):
    h=Host();w=Worker(plan(),directory=tmp_path/'journal',run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);w.ensure()
    d=Docker();networks={'default':expected()}
    def factory(worker,networks,**kwargs):return NetworkGuard(worker,networks,docker=d,plugin=lambda:copy.deepcopy(d.plugin),**kwargs)
    w.network_factory=factory
    g=factory(w,networks)
    return h,w,d,g


def test_birth_idempotence_mark_use_cleanup_and_kernel_dependency(fixture):
    h,w,d,g=fixture
    assert g.operate('preflight')['status']=='verified'
    assert not w.read().get('networks')
    assert g.operate('ensure')['status']=='active'
    row=w.read()['networks']['default'];assert row['id'] in d.networks and not row['used']
    assert g.operate('ensure')['status']=='active' and len(d.calls)==1
    with pytest.raises(ManagementError,match='Docker network cleanup'):w.cleanup()
    g.operate('mark-used');assert w.read()['networks']['default']['used']
    g.operate('cleanup');g.operate('verify-cleaned');w.cleanup();w.operate('verify-cleaned')
    assert d.calls[-1]==('delete',row['id']) and set(h.links)=={'eth0'}


def test_lost_create_response_requires_explicit_recovery_without_recreate(fixture):
    h,w,d,g=fixture;d.after='create'
    with pytest.raises(RuntimeError,match='lost'):g.operate('ensure')
    row=w.read()['networks']['default'];assert row['attempted'] and row['id'] is None
    with pytest.raises(NetworkError):g.operate('ensure')
    assert g.operate('recover')['status']=='active' and len(d.calls)==1
    assert w.read()['networks']['default']['id']==next(iter(d.networks))


def test_lost_delete_response_resumes_cleanup_not_creation(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');d.after='delete'
    with pytest.raises(RuntimeError,match='lost'):g.operate('cleanup')
    assert w.read()['networks']['default']['phase']=='deleting'
    assert g.operate('recover')['status']=='cleaned'
    assert len([x for x in d.calls if x[0]=='create'])==1
    w.cleanup()


@pytest.mark.parametrize('operation',['ensure','mark-used','cleanup','recover','restore','preflight'])
def test_same_name_config_labels_with_new_id_is_preserved(fixture,operation):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');old=next(iter(d.networks));v=copy.deepcopy(d.networks[old]);d.remove_external(old)
    replacement='f'*64;v['Id']=replacement;d.networks[replacement]=v
    calls=copy.deepcopy(d.calls)
    with pytest.raises(NetworkError,match='replaced'):g.operate(operation)
    assert d.calls==calls and replacement in d.networks
    assert w.read()['networks']['default']['id']==old


def test_used_network_absence_requires_explicit_restore_keeps_history(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');old=copy.deepcopy(w.read()['networks']['default']);d.remove_external(old['id'])
    for action in ('ensure','recover','mark-used'):
        with pytest.raises(NetworkError,match='explicit restore'):g.operate(action)
    g.operate('restore');new=w.read()['networks']['default']
    assert new['id']!=old['id'] and new['nonce']!=old['nonce'] and not new['used']
    assert new['history'][0]['id']==old['id'] and new['history'][0]['used']
    assert new['expected']==old['expected']


def test_even_never_used_observed_id_cannot_be_silently_replaced(fixture):
    h,w,d,g=fixture;g.operate('ensure');old=next(iter(d.networks));d.remove_external(old)
    with pytest.raises(NetworkError,match='explicit restore'):g.operate('recover')
    assert len(d.calls)==1


def test_legacy_network_not_adopted_or_removed(fixture):
    h,w,d,g=fixture
    d.networks['c'*64]={'Id':'c'*64,'Name':expected()['network']}
    for action in ('preflight','ensure','cleanup'):
        with pytest.raises(NetworkError,match='legacy'):g.operate(action)
    assert not d.calls and 'c'*64 in d.networks


@pytest.mark.parametrize('change',['subnet','gateway','tenant','reserved','host-count','bridge','vrf','nonce','driver','ipv6','plugin'])
def test_configuration_drift_blocks_mutation(fixture,change):
    h,w,d,g=fixture;g.operate('ensure');row=w.read()['networks']['default'];v=d.networks[row['id']]
    if change=='subnet':v['IPAM']['Config'][0]['Subnet']='10.99.0.0/24'
    elif change=='gateway':v['IPAM']['Config'][0]['Gateway']='10.1.0.99'
    elif change=='tenant':v['IPAM']['Options']['dnlab.tenant']='foreign'
    elif change=='reserved':v['IPAM']['Options']['dnlab.reserved']=''
    elif change=='host-count':v['IPAM']['Options']['dnlab.host-count']='99'
    elif change in ('bridge','vrf'):v['Options']['dnlab.'+change]='foreign'
    elif change=='nonce':v['Labels']['org.dnlab.management.creator']='f'*32
    elif change=='driver':v['Driver']='bridge'
    elif change=='ipv6':v['EnableIPv6']=False
    elif change=='plugin':d.plugin['networks'][row['id']]['bridge']='foreign'
    before=len(d.calls)
    with pytest.raises(NetworkError):g.operate('cleanup')
    assert len(d.calls)==before and row['id'] in d.networks


def test_cleanup_preflight_checks_endpoints_before_deletion(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');identity=next(iter(d.networks));d.networks[identity]['Containers']={'v':{'Name':'vd'}}
    with pytest.raises(NetworkError,match='endpoints'):g.operate('preflight-cleanup')
    with pytest.raises(NetworkError,match='endpoints'):g.operate('cleanup')
    assert len(d.calls)==1


def test_plugin_residue_blocks_restore_and_absent_cleanup(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');identity=next(iter(d.networks));d.networks.pop(identity)
    for action in ('restore','cleanup','recover'):
        with pytest.raises(NetworkError,match='plugin'):g.operate(action)
    assert len(d.calls)==1


def test_ambiguous_transport_error_never_means_absence(fixture):
    h,w,d,g=fixture;g.operate('ensure');d.failure='HTTP 500 from Docker'
    before=len(d.calls)
    for action in ('ensure','cleanup','restore'):
        with pytest.raises(NetworkError,match='HTTP 500'):g.operate(action)
    assert len(d.calls)==before


def test_intent_and_id_saved_before_use_and_create_failure_is_durable(fixture,monkeypatch):
    h,w,d,g=fixture;original=d.create
    def create(config):
        r=w.read()['networks']['default'];assert r['attempted'] and r['nonce']==config['Labels']['org.dnlab.management.creator'] and r['id'] is None
        return original(config)
    monkeypatch.setattr(d,'create',create);g.operate('ensure');g.operate('mark-used')
    assert w.read()['networks']['default']['id'] in d.networks


def test_failed_journal_save_prevents_docker_create(fixture,monkeypatch):
    h,w,d,g=fixture
    def fail(*args):raise OSError('fsync failed')
    monkeypatch.setattr(w,'save',fail)
    with pytest.raises(OSError):g.operate('ensure')
    assert not d.calls


def test_restore_lost_create_ack_resumes_same_generation_and_history(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');old=next(iter(d.networks));d.remove_external(old);d.after='create'
    with pytest.raises(RuntimeError,match='lost'):g.operate('restore', 'c'*32)
    row=w.read()['networks']['default'];nonce=row['nonce'];assert row['restore_id']=='c'*32 and row['id'] is None
    assert g.operate('recover')['status']=='active'
    row=w.read()['networks']['default'];assert row['nonce']==nonce and len(row['history'])==1
    before=len(d.calls);g.operate('restore','c'*32);assert len(d.calls)==before
    d.remove_external(row['id']);g.operate('restore','d'*32)
    with pytest.raises(NetworkError,match='historical'):g.operate('restore','c'*32)


def test_explicit_new_kernel_generation_checks_closed_network_before_provision(fixture):
    h,w,d,g=fixture;g.operate('ensure');old_nonce=w.read()['networks']['default']['nonce'];g.operate('cleanup');w.cleanup()
    p=copy.deepcopy(w.plan);p['generation']='b'*32
    new=Worker(p,directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel)
    new.network_factory=w.network_factory
    guard=NetworkGuard(new,g.networks,docker=d,plugin=lambda:copy.deepcopy(d.plugin))
    assert guard.operate('preflight')['status']=='verified'
    new.operate('provision');guard.operate('ensure')
    assert new.read()['networks']['default']['nonce']!=old_nonce
    assert len(list(w.directory.glob('*-'+'a'*32+'.json')))==1
    guard.operate('cleanup');new.cleanup()


@pytest.mark.parametrize('field',['host_count','reserved','pool'])
def test_plugin_pool_drift_blocks_reuse_and_cleanup(fixture,field):
    h,w,d,g=fixture;g.operate('ensure');row=next(iter(d.plugin['pools'].values()))
    row[field]=99 if field=='host_count' else [] if field=='reserved' else '10.99.0.0/24'
    before=len(d.calls)
    with pytest.raises(NetworkError,match='IPAM'):g.operate('cleanup')
    assert len(d.calls)==before


def test_restore_refuses_unqualified_bridge_port_without_mutation(fixture):
    h,w,d,g=fixture;g.operate('ensure');g.operate('mark-used');old=next(iter(d.networks));d.remove_external(old)
    h.links['alien']=dict(ifname='alien',ifindex=90,master='bm1');before=len(d.calls)
    with pytest.raises(NetworkError,match='attachment cleanup'):g.operate('preflight-restore','c'*32)
    with pytest.raises(NetworkError,match='attachment cleanup'):g.operate('restore','c'*32)
    assert len(d.calls)==before and 'alien' in h.links


@pytest.mark.parametrize('status,body,absent,missing',[(404,b'{"message":"network not found"}',True,True),(500,b'{"message":"driver unavailable"}',True,False),
    (404,b'not json',True,False),(200,b'',True,False),(200,b'[]',True,False)])
def test_http_inspection_only_structured_404_is_absent(monkeypatch,status,body,absent,missing):
    import dnlab_multinode.services.management_network_host as module
    class Sock:
        def settimeout(self,*args):pass
        def connect(self,*args):pass
    class Connection:
        sock=None
        def __init__(self,*args,**kwargs):pass
        def request(self,*args,**kwargs):pass
        def getresponse(self):return type('Response',(),{'status':status,'read':lambda self:body})()
        def close(self):pass
    monkeypatch.setattr(module.socket,'socket',lambda *args:Sock())
    monkeypatch.setattr(module.http.client,'HTTPConnection',Connection)
    if missing:assert module.Docker('/fake.sock').inspect('missing') is None
    else:
        with pytest.raises(NetworkError):module.Docker('/fake.sock').inspect('original')


def test_real_journal_two_host_restore_retry_keeps_completed_host_generation(tmp_path):
    import json
    from dnlab_multinode.services import netsetup
    from dnlab_multinode.models.state import DeploymentState, MgmtState
    from dnlab_multinode.services.realnet_vni import identity_key
    clients={};guards={};daemons={};workers={};plans={};definitions={};fails=[True]
    for index,host in enumerate(('master','worker1')):
        h=Host();w=Worker(plan(),directory=tmp_path/host,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);w.ensure()
        d=Docker();wanted=expected();wanted.update(host_index=index,host_count=2)
        g=NetworkGuard(w,{'default':wanted},docker=d,plugin=lambda d=d:copy.deepcopy(d.plugin));g.operate('ensure');g.operate('mark-used')
        w.network_factory=lambda worker,networks,d=d,**kwargs:NetworkGuard(worker,networks,docker=d,plugin=lambda:copy.deepcopy(d.plugin),**kwargs)
        guards[host]=g;daemons[host]=d;workers[host]=w;plans[host]=w.plan;definitions[host]=g.networks
        d.remove_external(w.read()['networks']['default']['id'])
        class Client:
            def __init__(self,host):self.host=host
            def run_input(self,command,payload,**kwargs):
                value=json.loads(payload);action=value['action'].removeprefix('network-')
                if self.host=='worker1' and action=='restore' and fails[0]:fails[0]=False;raise RuntimeError('crash before worker restore')
                return json.dumps(guards[self.host].operate(action,value.get('operation_id')))
        clients[host]=Client(host)
    state=DeploymentState(lab_name='breakout-alpha',topology_file='fixture')
    state.mgmt=MgmtState(subnet='10.1.0.0/24',gateway='10.1.0.254',bridge='bm1',vrf='vrfa',vxlan_id=70001,vxlan_iface='vm1')
    state.mgmt.infrastructure=dict(schema=1,generation='a'*32,plans=plans,networks=definitions,reservations={'default':dict(key=identity_key([state.lab_name,'management','default','multipoint']),vni=70001,token='c'*32)})
    with pytest.raises(RuntimeError,match='crash'):netsetup.network_action(state,clients,'restore')
    master=copy.deepcopy(workers['master'].read()['networks']['default'])
    netsetup.network_action(state,clients,'recover')
    assert workers['master'].read()['networks']['default']==master
    assert len([v for v in daemons['master'].calls if v[0]=='create'])==2
    assert all(len(w.read()['networks']['default']['history'])==1 for w in workers.values())
    # Repair a single host without replacing an intact peer's generation.
    untouched=copy.deepcopy(workers['master'].read()['networks']['default'])
    daemons['worker1'].remove_external(workers['worker1'].read()['networks']['default']['id'])
    netsetup.network_action(state,clients,'restore',targets={'worker1':['default']})
    assert workers['master'].read()['networks']['default']==untouched
    assert len([v for v in daemons['master'].calls if v[0]=='create'])==2
    assert len(workers['worker1'].read()['networks']['default']['history'])==2
    netsetup.network_action(state,clients,'cleanup')
    assert state.mgmt.infrastructure['network_phase']=='cleaned'
    for w in workers.values():w.cleanup()


def test_docker_gate_rejects_image_tags_before_fixture_creation(tmp_path):
    import importlib.util
    from pathlib import Path
    source=Path(__file__).resolve().parents[2]/'runtime'/'tools'/'management_network_identity_smoke.py'
    spec=importlib.util.spec_from_file_location('network_gate',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=tmp_path/'should-not-exist'
    with pytest.raises(RuntimeError,match='immutable image ID'):module.run(str(output),'python:3.13-slim','0'*64)
    assert not output.exists()
