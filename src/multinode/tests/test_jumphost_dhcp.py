"""Real asset/journal updates with simulated Docker and qualified dnsmasq."""
import copy
import os
from pathlib import Path
import pytest
from dnlab_multinode.services import jumphost
from dnlab_multinode.services.jumphost_host import JumphostError, dhcp_files
from tests.test_jumphost_host import World, config


def content(ip='198.18.0.11', dns='192.0.2.53'):
    return ('interface=eth1\nbind-dynamic\ndhcp-authoritative\npid-file=/run/dnlab-dnsmasq.pid\n'
            'dhcp-range=set:mgmt,198.18.0.0,static,12h\n'
            'dhcp-option=tag:mgmt,option:router,198.18.0.254\n'
            f'dhcp-option=tag:mgmt,option:dns-server,{dns}\n'
            f'dhcp-host=02:00:00:12:34:56,{ip}\n')


def install_service(worker):
    service={'pid':42,'start':'1234'};calls=[];fault={'reload':False}
    def run(record, action='inspect', expected=None):
        calls.append(action)
        if expected is not None and service!=expected:raise JumphostError('DHCP process generation differs')
        if action=='reload':
            worker.dhcp_verify(record)
            if fault['reload']:raise JumphostError('lost reload acknowledgement')
            return {'service':copy.deepcopy(service),'reload_verified':True}
        return copy.deepcopy(service)
    worker.dhcp_service=run
    return service,calls,fault


@pytest.fixture
def world(tmp_path):
    cfg=config();cfg['dhcp']=content();w=World(cfg);worker=w.worker(tmp_path/'journal')
    record=worker.operate('ensure',cfg);service,calls,fault=install_service(worker)
    return w,worker,record,service,calls,fault


def request(record, value=None, request_id='a'*32):
    return {'container':record['config']['name'],'generation':record['config']['generation'],
            'content':value or content('198.18.0.12','192.0.2.54'),'request_id':request_id}


def test_split_birth_and_refresh_keep_original_container_and_static_file(world):
    w,worker,r,service,calls,fault=world;cfg=copy.deepcopy(r['config']);main=copy.deepcopy(r['dhcp_assets']['files']['main'])
    result=worker.operate('dhcp-refresh',request(r));assert result['phase']=='active'
    assert result['config']==cfg and result['container_id']==r['container_id']
    assert result['dhcp_assets']['files']['main']==main
    assert result['dhcp_current']==dhcp_files(request(r)['content'])
    assert calls==['inspect','inspect','reload']
    assert worker.operate('dhcp-refresh',request(r))['dhcp_history']==result['dhcp_history']
    assert calls.count('reload')==1
    assert worker.operate('delete')['cleanup_verified']
    assert not worker.dhcp_directory(r).exists()


@pytest.mark.parametrize('change',['generation','container','structural','image','file','process'])
def test_preflight_conflicts_preserve_assets_and_workload(world,change):
    w,worker,r,service,calls,fault=world;req=request(r)
    if change=='generation':req['generation']='f'*32
    if change=='container':req['container']='foreign'
    if change=='structural':req['content']=req['content'].replace('interface=eth1','interface=eth2')
    if change=='image':w.values[r['container_id']]['Image']='sha256:'+'f'*64
    if change=='file':(worker.dhcp_directory(r)/'hosts').write_text('foreign')
    if change=='process':
        fault['reload']=True
        with pytest.raises(JumphostError):worker.operate('dhcp-refresh',req)
        fault['reload']=False;service['start']='replacement'
    before={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()};old=copy.deepcopy(w.values)
    with pytest.raises(JumphostError):
        if change=='process':worker.operate('recover')
        else:worker.operate('dhcp-refresh',req)
    assert before=={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()}
    assert w.values==old


def test_recover_lost_reload_ack_with_same_request_and_service(world):
    w,worker,r,service,calls,fault=world;fault['reload']=True
    with pytest.raises(JumphostError):worker.operate('dhcp-refresh',request(r))
    assert worker.read()['phase']=='recovery_required'
    with pytest.raises(JumphostError,match='explicit DHCP recovery'):worker.operate('dhcp-refresh',request(r))
    fault['reload']=False
    assert worker.operate('recover')['phase']=='active'
    assert worker.operate('dhcp-refresh',request(r))['dhcp_history'][0]['request_id']=='a'*32


def test_recover_crash_after_replace_before_file_proof(world,monkeypatch):
    w,worker,r,service,calls,fault=world;replace=os.replace;target=worker.dhcp_directory(r)/'hosts';armed=True
    def interrupted(src,dst):
        nonlocal armed
        replace(src,dst)
        if Path(dst)==target and armed:armed=False;raise OSError('replace acknowledgement lost')
    with monkeypatch.context() as patch:
        patch.setattr(os,'replace',interrupted)
        with pytest.raises(OSError):worker.operate('dhcp-refresh',request(r))
    assert worker.operate('recover')['phase']=='active'
    assert worker.read()['dhcp_current']['hosts'].endswith('198.18.0.12\n')


def test_save_failure_prevents_asset_mutation(world,monkeypatch):
    w,worker,r,service,calls,fault=world;before={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()}
    monkeypatch.setattr(worker,'save',lambda record:(_ for _ in ()).throw(OSError('fsync')))
    with pytest.raises(OSError):worker.operate('dhcp-refresh',request(r))
    assert before=={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()}


def test_legacy_layout_not_adopted(world):
    w,worker,r,service,calls,fault=world
    r['dhcp_layout']=1;worker.save(r);before=worker.path.read_bytes()
    with pytest.raises(JumphostError,match='explicit new-generation layout'):worker.operate('dhcp-refresh',request(r))
    assert worker.path.read_bytes()==before


def test_request_id_conflicts_and_historical_replay(world):
    w,worker,r,service,calls,fault=world;worker.operate('dhcp-refresh',request(r))
    with pytest.raises(JumphostError,match='content conflict'):worker.operate('dhcp-refresh',request(r,content('198.18.0.13')))
    worker.operate('dhcp-refresh',request(r,content('198.18.0.13'),'b'*32))
    with pytest.raises(JumphostError,match='superseded'):worker.operate('dhcp-refresh',request(r))
