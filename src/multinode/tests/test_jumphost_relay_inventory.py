"""Relay publication, persistent bootstrap and guarded crash recovery."""
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from dnlab_multinode.services import jumphost
from dnlab_multinode.services.jumphost_host import JumphostError
from tests.test_jumphost_host import World, config

SOURCE = Path(__file__).resolve().parents[1] / 'jumphost/inventory.py'
spec = importlib.util.spec_from_file_location('inventory', SOURCE)
inventory = importlib.util.module_from_spec(spec); spec.loader.exec_module(inventory)


def payload():
    return dict(lab='breakout-alpha', generation='1'*32, container_id='1'*64,
                request_id='2'*32, vds='r1=runtime1\n',
                relays='runtime1=192.0.2.10:23001:test-key\n', motd='Lab fixture\n')


@pytest.mark.parametrize('problem', ['missing','key','port','host'])
def test_incomplete_inventory_rejected_without_publication(problem):
    relay = {'runtime1':dict(host='192.0.2.10', port=23001, api_key='test-key')}
    if problem == 'missing': relay.clear()
    if problem == 'key': relay['runtime1']['api_key'] = ''
    if problem == 'port': relay['runtime1']['port'] = 0
    if problem == 'host': relay['runtime1']['host'] = '0.0.0.0\nsecret'
    with pytest.raises(RuntimeError): jumphost.render_relay_inventory({'r1':'runtime1'}, relay)


def test_placement_filters_old_allowlist():
    r = SimpleNamespace(node='r1', host='worker2', container='runtime1')
    relay = lambda host,key: SimpleNamespace(host=host, bind_ip='192.0.2.10', port=23001, api_key=key, allowed=['runtime1','obsolete'])
    state = SimpleNamespace(node_runtime={'r1':r}, runtime_relays={'worker1':relay('worker1','old'), 'worker2':relay('worker2','new')})
    assert jumphost.relay_inventory_from_state(state) == {'runtime1':dict(host='192.0.2.10', port=23001, api_key='new')}
    state.runtime_relays['worker2'].allowed=[]
    with pytest.raises(RuntimeError, match='placement or allowlist'): jumphost.relay_inventory_from_state(state)


def test_persistent_inventory_restores_both_maps_and_permissions(tmp_path):
    desired=payload()
    inventory.publish(dict(action='apply',previous=None,desired=desired), tmp_path, os.getgid())
    (tmp_path/'dnlab-relays').write_text('stale\n')
    inventory.publish(dict(action='restore'), tmp_path, os.getgid())
    assert (tmp_path/'dnlab-relays').read_text() == desired['relays']
    assert (tmp_path/'dnlab-vds').read_text() == desired['vds']
    assert (tmp_path/'dnlab-relays').stat().st_mode & 0o777 == 0o640
    assert (tmp_path/'dnlab-inventory.json').stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('target', ['dnlab-vds','dnlab-relays','dnlab-inventory.json'])
def test_foreign_symlink_refused_before_write(tmp_path,target):
    foreign=tmp_path/'foreign';foreign.write_text('preserve')
    (tmp_path/target).symlink_to(foreign)
    with pytest.raises(RuntimeError, match='ownership'):
        inventory.publish(dict(action='apply',previous=None,desired=payload()),tmp_path,os.getgid())
    assert foreign.read_text()=='preserve'


def test_publication_interruption_restores_authoritative_bundle(tmp_path,monkeypatch):
    replace=os.replace
    def interrupted(source,target):
        if str(target).endswith('dnlab-relays'): raise OSError('lost write')
        return replace(source,target)
    monkeypatch.setattr(os,'replace',interrupted)
    with pytest.raises(OSError): inventory.publish(dict(action='apply',previous=None,desired=payload()),tmp_path,os.getgid())
    monkeypatch.setattr(os,'replace',replace)
    inventory.publish(dict(action='restore'),tmp_path,os.getgid())
    assert (tmp_path/'dnlab-relays').read_text()==payload()['relays']


def test_worker_recovers_lost_publication_reply(tmp_path):
    world=World(config());worker=world.worker(tmp_path/'journal')
    worker.operate('ensure', world.cfg)
    saved={}; original=world.run; lost=[True]
    def run(argv,**kwargs):
        if argv[:3]==['docker','exec','-i']:
            request=json.loads(kwargs['input'])
            if request['action']=='inspect': return json.dumps(saved.get('current'))
            assert worker.read()['inventory_operation']['desired']==payload()
            saved['current']=request['desired']
            if lost[0]: lost[0]=False; raise JumphostError('lost publication reply')
            return json.dumps(saved['current'])
        return original(argv,**kwargs)
    worker.run=run
    with pytest.raises(JumphostError, match='lost publication'):worker.operate('inventory-refresh',payload())
    assert worker.read()['phase']=='recovery_required'
    with pytest.raises(JumphostError, match='explicit inventory'):worker.operate('inventory-refresh',payload())
    assert worker.operate('recover')['inventory_current']==payload()
    assert worker.operate('inventory-refresh',payload())['phase']=='active'
    assert sum(v[:2]==['docker','create'] for v in world.calls)==1
    assert not any(v[:2] in (['docker','kill'],['docker','rm']) for v in world.calls)


def test_replaced_container_refused_before_inventory_exec(tmp_path):
    world=World(config());worker=world.worker(tmp_path/'journal');worker.operate('ensure',world.cfg)
    value=world.values.pop('1'*64);value['Id']='f'*64;world.values['f'*64]=value
    before=copy.deepcopy(world.calls)
    with pytest.raises(JumphostError,match='generation replaced'):worker.operate('inventory-refresh',payload())
    assert not any(c[:2]==['docker','exec'] for c in world.calls[len(before):])
    assert not worker.read().get('inventory_operation')


def test_deploy_publishes_after_two_worker_relays_are_saved(monkeypatch,tmp_path):
    from dnlab_multinode.controllers import deploy
    from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState,JumphostState
    ctrl=deploy.DeployController(str(tmp_path/'lab.yml'))
    ctrl._state=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'lab.yml'))
    ctrl._state.jumphost=JumphostState(node='master',container='jh',mgmt_ip='',host_ip='',ext_network='',password='',generation='b'*32)
    ctrl._state.node_runtime={name:NodeRuntimeState(node=name,host=host,container='runtime-'+name) for name,host in [('r1','worker1'),('r2','worker2')]}
    ctrl._clients={'master':object()};ctrl._underlay_ips={};events=[]
    results={host:dict(container='relay-'+host,bind_ip=ip,port=23001,api_key='key-'+host,allowed=['runtime-'+name]) for host,ip,name in [('worker1','192.0.2.11','r1'),('worker2','192.0.2.12','r2')]}
    monkeypatch.setattr(deploy.runtime_relay_svc,'deploy_runtime_relays',lambda *a:results)
    monkeypatch.setattr(deploy.state_svc,'save_state',lambda state,path:events.append('save'))
    def refresh(lab,client,vds,relays,**kwargs):
        assert events==['save']
        assert vds=={'r1':'runtime-r1','r2':'runtime-r2'}
        assert relays['runtime-r2']['api_key']=='key-worker2'
        assert kwargs['generation']=='b'*32
        events.append('refresh')
    monkeypatch.setattr(deploy.jumphost,'refresh_jumphost_inventory',refresh)
    ctrl._deploy_runtime_relays(SimpleNamespace(name='demo'),object())
    assert events==['save','refresh']


def test_restart_entrypoint_uses_persistent_inventory_over_old_environment(tmp_path):
    import subprocess
    desired=payload()
    inventory.publish(dict(action='apply',previous=None,desired=desired),tmp_path,os.getgid())
    entry=(SOURCE.parent/'entrypoint.sh').read_text()
    section=entry[entry.index('# A qualified refresh'):entry.index('# ── Routing / NAT')]
    section=section.replace('/etc/',str(tmp_path)+'/')
    restore='from pathlib import Path; import runpy; m=runpy.run_path('+repr(str(SOURCE))+'); m["publish"]({"action":"restore"},Path('+repr(str(tmp_path))+'),'+str(os.getgid())+')'
    import shlex
    section=section.replace('python3 /usr/local/lib/dnlab-inventory.py --restore','python3 -c '+shlex.quote(restore))
    # The persistent inventory branch must still launch DHCP on startup.
    (tmp_path/'dnsmasq.d').mkdir();(tmp_path/'dnsmasq.d/dnlab-mgmt.conf').write_text('fixture')
    bin_dir=tmp_path/'bin';bin_dir.mkdir(); marker=tmp_path/'dhcp-started'
    for name,body in [('ip','exit 0'),('dnsmasq','touch '+str(marker))]:
        path=bin_dir/name;path.write_text('#!/bin/sh\n'+body+'\n');path.chmod(0o755)
    result=subprocess.run(['bash','-ec',section],env={'PATH':str(bin_dir)+':/usr/bin:/bin','JUMPHOST_RELAY_MAP':'obsolete=192.0.2.1:1:old','JUMPHOST_VD_LIST':'obsolete'},capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert marker.exists()
    assert (tmp_path/'dnlab-relays').read_text()==desired['relays']
    assert (tmp_path/'dnlab-vds').read_text()==desired['vds']


@pytest.mark.parametrize('field,value',[('relays',''),('vds','r1=runtime1\nr2=runtime1\n'),('relays','runtime1=192.0.2.10:0:key\n')])
def test_worker_refuses_incomplete_inventory_before_exec(tmp_path,field,value):
    world=World(config());worker=world.worker(tmp_path/'journal');worker.operate('ensure',world.cfg)
    request=dict(payload(),**{field:value});before=len(world.calls)
    with pytest.raises(JumphostError):worker.operate('inventory-refresh',request)
    assert not any(v[:2]==['docker','exec'] for v in world.calls[before:])
    assert worker.read()['phase']=='active'
