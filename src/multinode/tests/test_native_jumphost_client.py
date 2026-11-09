"""Inert end-to-end inventory -> vd -> ID request and guard profiles."""
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import pytest
from dnlab_multinode.services import jumphost
from dnlab_multinode.services.jumphost_host import JumphostError
from tests.test_jumphost import _fake_vd_relay_client_bin
from tests.test_jumphost_host import World,config
from tests.test_jumphost_relay_inventory import payload

CLIENT=Path(__file__).resolve().parents[1]/'jumphost/vd-relay-client'
loader=importlib.machinery.SourceFileLoader('native_vd_client',str(CLIENT))
spec=importlib.util.spec_from_loader(loader.name,loader);client=importlib.util.module_from_spec(spec);loader.exec_module(client)


@pytest.mark.parametrize('action',['connect','log'])
def test_vd_passes_native_id_from_rendered_inventory(tmp_path,action):
    name='native-R1';identity='a'*64
    vds,relays=jumphost.render_relay_inventory({'R1':name},{name:{'host':'127.0.0.1','port':19000,'api_key':'key','runtime_backend':'custom','container_id':identity}})
    env,marker=_fake_vd_relay_client_bin(tmp_path)
    mapping=tmp_path/'vds';mapping.write_text(vds);routing=tmp_path/'relays';routing.write_text(relays)
    env.update(VD_LIST_FILE=str(mapping),VD_RELAY_FILE=str(routing))
    result=subprocess.run([str(CLIENT.with_name('vd')),action,'R1'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode==0 and marker.read_text().strip().endswith(identity)
    assert 'key native-R1' in marker.read_text()


@pytest.mark.parametrize('suffix',['custom:short','custom:','other:'+'a'*64,'custom:'+'A'*64])
def test_vd_never_downgrades_malformed_native_inventory(tmp_path,suffix):
    env,marker=_fake_vd_relay_client_bin(tmp_path);mapping=tmp_path/'vds';mapping.write_text('R1=native-R1\n')
    routing=tmp_path/'relays';routing.write_text('native-R1=127.0.0.1:19000:key:'+suffix+'\n')
    env.update(VD_LIST_FILE=str(mapping),VD_RELAY_FILE=str(routing))
    result=subprocess.run([str(CLIENT.with_name('vd')),'connect','R1'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode!=0 and not marker.exists()


def test_python_log_client_encodes_id_and_never_falls_back(monkeypatch):
    calls=[]
    def rejected(*args):calls.append(args);raise OSError('inert rejection')
    monkeypatch.setattr(client,'_open',rejected)
    with pytest.raises(OSError):client._run_log(['127.0.0.1','19000','key','native-R1','all','0','a'*64])
    assert calls==[('127.0.0.1','19000','LOG_ID','key','native-R1','a'*64,'all','0')]


def test_python_connect_client_encodes_id(monkeypatch):
    calls=[]
    def rejected(*args):calls.append(args);raise OSError('inert rejection')
    monkeypatch.setattr(client,'_open',rejected)
    with pytest.raises(OSError):client._run_connect(['127.0.0.1','19000','key','native-R1','a'*64])
    assert calls==[('127.0.0.1','19000','CONNECT_ID','key','native-R1','a'*64)]


def test_worker_refuses_native_inventory_without_image_capability(tmp_path):
    world=World(config());worker=world.worker(tmp_path/'journal');worker.operate('ensure',world.cfg)
    request=payload();request['relays']=request['relays'].rstrip() + ':custom:'+'a'*64+'\n'
    before=len(world.calls)
    with pytest.raises(JumphostError,match='capability'):worker.operate('inventory-refresh',request)
    assert not worker.read().get('inventory_operation')
    assert not any(argv[:2]==['docker','exec'] for argv in world.calls[before:])


@pytest.mark.parametrize('identity',['short','A'*64,''])
def test_renderer_refuses_invalid_custom_identity(identity):
    with pytest.raises(RuntimeError):jumphost.render_relay_inventory({'R1':'native-R1'},{'native-R1':{
        'host':'127.0.0.1','port':19000,'api_key':'key','runtime_backend':'custom','container_id':identity}})


def test_worker_accepts_and_recovers_only_original_native_inventory(tmp_path):
    import json
    world=World(config())
    world.image['Config']['Labels']['io.dnlab.jumphost.capabilities']='qualified-relay-inventory-v1'
    base_run=world.run
    def create_with_inherited_labels(argv,**kwargs):
        result=base_run(argv,**kwargs)
        if argv[:2]==['docker','create']:
            world.values[result]['Config']['Labels'].update(world.image['Config']['Labels'])
        return result
    world.run=create_with_inherited_labels
    worker=world.worker(tmp_path/'journal');worker.operate('ensure',world.cfg)
    desired=payload();desired['relays']=desired['relays'].rstrip()+':custom:'+'a'*64+'\n'
    saved={'value':None};original=worker.run;lose=[True]
    def run(argv,**kwargs):
        if argv[:2]==['docker','exec']:
            request=json.loads(kwargs['input'])
            if request['action']=='inspect':return json.dumps(saved['value'])
            saved['value']=request['desired']
            if lose[0]:lose[0]=False;raise JumphostError('inert lost native publication reply')
            return json.dumps(saved['value'])
        return original(argv,**kwargs)
    worker.run=run
    with pytest.raises(JumphostError,match='lost native'):worker.operate('inventory-refresh',desired)
    assert worker.read()['inventory_operation']['desired']==desired
    result=worker.operate('recover')
    assert result['inventory_current']==desired and result['phase']=='active'
    assert worker.operate('inventory-refresh',desired)['inventory_current']==desired


def test_persistent_native_inventory_restores_original_id(tmp_path):
    import os
    from tests.test_jumphost_relay_inventory import inventory
    desired=payload();desired['relays']=desired['relays'].rstrip()+':custom:'+'a'*64+'\n'
    inventory.publish({'action':'apply','previous':None,'desired':desired},tmp_path,os.getgid())
    (tmp_path/'dnlab-relays').unlink()
    inventory.publish({'action':'restore'},tmp_path,os.getgid())
    assert (tmp_path/'dnlab-relays').read_text()==desired['relays']
    assert (tmp_path/'dnlab-relays').stat().st_mode&0o777==0o640
