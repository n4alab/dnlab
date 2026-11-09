"""Worker preflight recognizes only its own inode-bound structural chunks."""
import copy
import hashlib
import os
from unittest.mock import Mock

import pytest
from dnlab_multinode.services import jumphost_host as module
from tests.test_jumphost_host import World, config
from tests.test_jumphost_dhcp import content, request
from tests.test_dhcp_host_identity import proof


@pytest.fixture
def world(tmp_path):
    cfg=config();cfg['dhcp']=content();w=World(cfg);worker=w.worker(tmp_path/'journal')
    record=worker.operate('ensure',cfg)
    service=proof();service['container'].update(id=record['container_id'],image=record['image']['Id'],
        host=record['context'],started_at=record['started_at'],net_namespace=record['namespace'])
    service['net_namespace']=record['namespace']
    service['log']={'configuration_sha256':hashlib.sha256(record['dhcp_assets']['files']['main']['content'].encode()).hexdigest()}
    receipt={'service':service,'exit_verified':True}
    # Only process inventory is simulated. Worker/container/network/attachments,
    # files and durable progress use the production implementations.
    def closed(record,expected):
        worker.dhcp_preflight(record)
        assert expected==service
        return {'container':service['container'],'service_exit':receipt}
    worker.dhcp_structure_closed=closed
    desired=content('198.18.0.12','192.0.2.54').replace('12h','24h')
    req=request(record,desired)
    return w,worker,record,receipt,req


def test_writing_stage_keeps_birth_immutable_and_remains_pending_after_commit(world):
    w,worker,r,receipt,req=world;birth=copy.deepcopy(r['config']);files=copy.deepcopy(r['dhcp_assets'])
    with worker.locked():
        worker.begin_dhcp_structure_assets(r,req,receipt)
        assert worker.read()['dhcp_structure']['assets']['phase']=='prepared'
        result=worker.write_dhcp_structure_assets(r)
        worker.dhcp_preflight(r)
        assert worker.dhcp_shutdown_main(r,receipt['service'])==files['files']['main']['content']
    assert r['config']==birth and r['phase']=='dhcp_structure_pending'
    assert r['dhcp_assets']['files']==result
    assert {k:v['content'] for k,v in result.items()}==module.dhcp_files(req['content'])
    assert {k:v['identity'] for k,v in result.items()}=={k:v['identity'] for k,v in files['files'].items()}
    assert r['dhcp_structure']['receipt']==receipt


@pytest.mark.parametrize('target',['main','hosts','options'])
def test_worker_reopens_partial_pwrite_with_full_preflight_and_recovers(world,monkeypatch,target):
    w,worker,r,receipt,req=world
    with worker.locked():worker.begin_dhcp_structure_assets(r,req,receipt)
    original=os.pwrite;armed=[True]
    def interrupted(fd,data,offset):
        if os.fstat(fd).st_ino==r['dhcp_assets']['files'][target]['identity']['inode'] and armed[0]:
            armed[0]=False;original(fd,data[:max(1,len(data)//2)],offset)
            raise OSError('lost partial write')
        return original(fd,data,offset)
    with monkeypatch.context() as patch:
        patch.setattr(os,'pwrite',interrupted)
        with worker.locked(),pytest.raises(OSError,match='lost partial'):
            worker.write_dhcp_structure_assets(r)
    r=worker.read();before=worker.path.read_bytes()
    worker.dhcp_preflight(r)
    assert worker.path.read_bytes()==before,'readonly qualification mutated journal'
    with worker.locked():worker.write_dhcp_structure_assets(r)
    worker.dhcp_preflight(r)
    assert r['dhcp_structure']['assets']['phase']=='ready'


@pytest.mark.parametrize('change',['request','receipt','nonce','config','file','primary-matrix','action','root-phase','child-target'])
def test_foreign_or_unbound_progress_is_rejected_before_further_writes(world,change):
    w,worker,r,receipt,req=world
    with worker.locked():worker.begin_dhcp_structure_assets(r,req,receipt)
    op=r['dhcp_structure']
    if change=='request':op['request']['content']+='port=0\n'
    if change=='receipt':op['receipt']['service']['start']='foreign'
    if change=='nonce':r['nonce']='9'*32
    if change=='config':r['config']['env']['UNRELATED']='foreign'
    if change=='file':
        path=worker.dhcp_directory(r)/'hosts';path.rename(path.with_suffix('.old'));path.write_text('foreign')
    if change=='primary-matrix':r['dhcp_assets']['files']['hosts']['content']='foreign'
    if change=='action':r['action']='ensure'
    if change=='root-phase':r['phase']='active'
    if change=='child-target':op['assets']['files']['options']['new']='foreign'
    directory=worker.dhcp_directory(r)
    before={p.name:p.read_bytes() for p in directory.iterdir()} if directory.exists() else {}
    with pytest.raises(module.JumphostError):worker.write_dhcp_structure_assets(r)
    assert before==({p.name:p.read_bytes() for p in directory.iterdir()} if directory.exists() else {})


def test_save_failure_prevents_any_asset_mutation(world,monkeypatch):
    w,worker,r,receipt,req=world
    before={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()}
    monkeypatch.setattr(worker,'save',Mock(side_effect=OSError('directory fsync failed')))
    with pytest.raises(OSError):worker.begin_dhcp_structure_assets(r,req,receipt)
    assert before=={p.name:p.read_bytes() for p in worker.dhcp_directory(r).iterdir()}


def test_shutdown_or_attachment_conflict_prevents_intent_and_writes(world,monkeypatch):
    w,worker,r,receipt,req=world;before=worker.path.read_bytes()
    monkeypatch.setattr(worker,'dhcp_structure_closed',Mock(side_effect=module.JumphostError('foreign service')))
    with pytest.raises(module.JumphostError):worker.begin_dhcp_structure_assets(r,req,receipt)
    assert 'dhcp_structure' not in r and worker.path.read_bytes()==before


def test_caller_cannot_change_durable_request_after_admission(world):
    w,worker,r,receipt,req=world
    with worker.locked():worker.begin_dhcp_structure_assets(r,req,receipt)
    desired=copy.deepcopy(r['dhcp_structure']['request'])
    req['content']='foreign';receipt['service']['start']='foreign'
    assert r['dhcp_structure']['request']==desired
    worker.dhcp_structure_assets(r).verify()


def test_closed_service_probe_rejects_running_before_write(world,monkeypatch):
    w,worker,r,receipt,req=world
    class Service:
        def __init__(self,*args):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def shutdown_status(self,expected):return {'state':'running','service':expected}
    monkeypatch.setattr(module,'DHCPHostService',Service)
    with pytest.raises(module.JumphostError,match='verified original DHCP shutdown'):
        module.Worker.dhcp_structure_closed(worker,r,receipt['service'])


def test_cleanup_refuses_partial_stage_then_cleans_ready_assets_with_history(world):
    w,worker,r,receipt,req=world
    with worker.locked():worker.begin_dhcp_structure_assets(r,req,receipt)
    before=copy.deepcopy(w.values)
    with pytest.raises(module.JumphostError,match='asset recovery required'):
        worker.operate('delete')
    assert w.values==before
    r=worker.read()
    with worker.locked():worker.write_dhcp_structure_assets(r)
    result=worker.operate('delete')
    assert result['phase']=='cleaned' and result['cleanup_verified']
    assert result['dhcp_structure_history'][0]['assets']['phase']=='ready'
    assert not worker.dhcp_directory(r).exists()


@pytest.mark.parametrize('action',['recover','ensure','segment-add','dhcp-refresh'])
def test_public_mutation_cannot_bypass_private_pending_stage(world,action):
    w,worker,r,receipt,req=world
    with worker.locked():worker.begin_dhcp_structure_assets(r,req,receipt)
    before=worker.path.read_bytes();calls=list(w.calls)
    with pytest.raises(module.JumphostError,match='private structural DHCP recovery required'):
        worker.operate(action)
    assert worker.path.read_bytes()==before and w.calls==calls
