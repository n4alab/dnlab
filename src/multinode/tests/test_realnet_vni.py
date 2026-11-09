import copy
import json
import multiprocessing
import os
import signal

import pytest

from dnlab_multinode.services.realnet_vni import Registry,identity_key
from dnlab_multinode.services.realnet_cleanup import scope
from dnlab_multinode.services.realnet_cleanup_host import OwnershipError,link_identity

CONTEXT={'boot_id':'fixture','device':1,'inode':2}


def request(lab='lab',worker='worker1'):
    suffix=lab.replace('-','')[-6:]
    return {'identity':[lab,'access',worker],
            'targets':{'master':{'name':'vx-m'+suffix,'bridge':'br-'+suffix,'local':'198.18.0.1',
                                 'remote':'198.18.0.2','underlay':'under0','dstport':14789},
                       worker:{'name':'vx-w'+suffix,'bridge':'br-'+suffix,'local':'198.18.0.2',
                               'remote':'198.18.0.1','underlay':'under0','dstport':14789}}}


def empty(hosts):return {host:{'context':copy.deepcopy(CONTEXT),'links':[]} for host in hosts}


def reserve_child(directory,lab,queue):
    try:
        registry=Registry(directory,pool=(65536,65599))
        registry.candidate=lambda key:65536
        row=registry.reserve([request(lab)],empty)
        queue.put(('ok',next(iter(row.values()))))
    except Exception as error:queue.put(('error',str(error)))


def crash_child(directory,moment):
    registry=Registry(directory,pool=(65536,65539));save=registry.save
    def crash(value):
        if moment=='after':save(value)
        os.kill(os.getpid(),signal.SIGKILL)
    registry.save=crash
    registry.reserve([request()],empty)


def test_forced_hash_collision_and_restart_preserve_allocation(tmp_path):
    registry=Registry(tmp_path/'vni',pool=(65536,65539));registry.candidate=lambda key:65536
    first=registry.reserve([request('lab-a'),request('lab-b')],empty)
    assert {r['vni'] for r in first.values()}=={65536,65537}
    restarted=Registry(registry.directory,pool=registry.pool)
    assert restarted.reserve([request('lab-b'),request('lab-a')],empty)==first


def test_concurrent_coordinator_processes_reserve_unique_vnis(tmp_path):
    ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
    processes=[ctx.Process(target=reserve_child,args=(tmp_path/'vni','lab-'+str(i),queue)) for i in range(8)]
    for process in processes:process.start()
    for process in processes:process.join(10);assert not process.is_alive() and process.exitcode==0
    results=[queue.get(timeout=2) for _ in processes]
    assert all(status=='ok' for status,_ in results),results
    assert len({r['vni'] for _,r in results})==8


@pytest.mark.parametrize('moment',['before','after'])
def test_actual_coordinator_sigkill_preserves_atomic_reservations(tmp_path,moment):
    ctx=multiprocessing.get_context('fork');directory=tmp_path/'vni'
    child=ctx.Process(target=crash_child,args=(directory,moment));child.start();child.join(10)
    assert child.exitcode==-signal.SIGKILL
    registry=Registry(directory,pool=(65536,65539))
    before=registry.read()
    assert bool(before['reservations'])==(moment=='after')
    result=registry.reserve([request()],empty)
    if moment=='after':assert next(iter(result.values()))['token']==next(iter(before['reservations'].values()))['token']
    assert len(registry.read()['reservations'])==1


def test_inventory_failure_keeps_existing_registry_unchanged(tmp_path):
    registry=Registry(tmp_path/'vni');registry.reserve([request()],empty)
    saved=(registry.directory/'registry.json').read_bytes()
    def unavailable(hosts):raise OwnershipError('worker unavailable')
    with pytest.raises(OwnershipError):registry.reserve([request('other')],unavailable)
    assert (registry.directory/'registry.json').read_bytes()==saved


def test_unmanaged_vni_is_skipped_without_touching_it(tmp_path):
    registry=Registry(tmp_path/'vni',pool=(65536,65539));registry.candidate=lambda key:65536
    inventory=empty({'master','worker1'})
    foreign={'ifname':'foreign','linkinfo':{'info_kind':'vxlan','info_data':{'id':65536}}}
    inventory['master']['links'].append(foreign);before=copy.deepcopy(inventory)
    row=registry.reserve([request()],lambda hosts:inventory)
    assert next(iter(row.values()))['vni']==65537 and inventory==before


def qualified(registry):
    req=request();row=next(iter(registry.reserve([req],empty).values()));req['previous']=row;req['proofs']={}
    inventory=empty(set(req['targets']))
    for host,target in req['targets'].items():
        alias='dnlab-runtime:realnet:'+scope(*req['identity'][:2],host)+':'+'a'*32
        bridge={'ifname':target['bridge'],'ifindex':3,'address':'02:00:00:00:00:01','ifalias':alias,'linkinfo':{'info_kind':'bridge'}}
        vx={'ifname':target['name'],'ifindex':4,'address':'02:00:00:00:00:02','ifalias':alias,'master':target['bridge'],
            'linkinfo':{'info_kind':'vxlan','info_data':{'id':row['vni'],'local':target['local'],'remote':target['remote'],'port':14789,'link':'under0'}}}
        inventory[host]['links']=[bridge,vx,{'ifname':'under0','ifindex':2}]
        req['proofs'][host]={'scope':scope(*req['identity'][:2],host),'context':CONTEXT,
                             'links':{v['ifname']:{'kind':v['linkinfo']['info_kind'],'identity':link_identity(v),'config':{}} for v in (bridge,vx)},'router':None,'firewall':[]}
    return req,row,inventory


def test_qualified_active_retry_is_read_only(tmp_path):
    registry=Registry(tmp_path/'vni');req,row,inventory=qualified(registry)
    saved=(registry.directory/'registry.json').read_bytes();snapshot=copy.deepcopy(inventory)
    assert registry.reserve([req],lambda hosts:inventory)=={row['key']:row}
    assert (registry.directory/'registry.json').read_bytes()==saved and inventory==snapshot


@pytest.mark.parametrize('change',['foreign_vni','alias','index','vni','remote','local','port','underlay','master','context','token','missing','bridge_missing','legacy'])
def test_active_conflict_refuses_without_renumber_or_registry_mutation(tmp_path,change):
    registry=Registry(tmp_path/'vni');req,row,inventory=qualified(registry)
    saved=(registry.directory/'registry.json').read_bytes();vx=inventory['master']['links'][1]
    if change=='foreign_vni':inventory['master']['links'].append({'ifname':'foreign','linkinfo':{'info_kind':'vxlan','info_data':{'id':row['vni']}}})
    if change=='alias':vx['ifalias']='foreign'
    if change=='index':vx['ifindex']=99
    if change=='vni':vx['linkinfo']['info_data']['id']+=1
    if change=='remote':vx['linkinfo']['info_data']['remote']='198.18.0.9'
    if change=='local':vx['linkinfo']['info_data']['local']='198.18.0.9'
    if change=='port':vx['linkinfo']['info_data']['port']=4789
    if change=='underlay':vx['linkinfo']['info_data']['link']='other'
    if change=='master':vx['master']='other'
    if change=='context':inventory['master']['context']['inode']=99
    if change=='token':req['previous']['token']='b'*32
    if change=='missing':inventory['master']['links'].pop(1)
    if change=='bridge_missing':inventory['master']['links'].pop(0)
    if change=='legacy':req.pop('proofs')
    with pytest.raises(OwnershipError):registry.reserve([req],lambda hosts:inventory)
    assert (registry.directory/'registry.json').read_bytes()==saved


def test_release_requires_successful_authoritative_cleanup_and_matching_generation(tmp_path):
    registry=Registry(tmp_path/'vni');row=next(iter(registry.reserve([request()],empty).values()))
    saved=(registry.directory/'registry.json').read_bytes()
    def incomplete():raise OwnershipError('cleanup pending')
    with pytest.raises(OwnershipError):registry.release([row],incomplete)
    assert (registry.directory/'registry.json').read_bytes()==saved
    with pytest.raises(OwnershipError):registry.release([{**row,'token':'b'*32}],lambda:None)
    assert (registry.directory/'registry.json').read_bytes()==saved
    checks=[];registry.release([row],lambda:checks.append('verified'))
    assert checks==['verified'] and registry.read()['reservations'][row['key']]['phase']=='released'
    replacement=next(iter(registry.reserve([request()],empty).values()))
    assert replacement['token']!=row['token']
    with pytest.raises(OwnershipError):registry.release([row],lambda:None)


def test_exhausted_pool_keeps_existing_reservations(tmp_path):
    registry=Registry(tmp_path/'vni',pool=(65536,65536));registry.reserve([request()],empty)
    saved=(registry.directory/'registry.json').read_bytes()
    with pytest.raises(OwnershipError,match='exhausted'):registry.reserve([request('second')],empty)
    assert (registry.directory/'registry.json').read_bytes()==saved


def test_state_roundtrip_keeps_worker_map_and_reservation_metadata():
    from dnlab_multinode.models.state import DeploymentState,RealNetState
    state=DeploymentState(lab_name='lab',topology_file='topo.yml',realnets=[RealNetState(name='access',bridge='br-test',vxlan_id=65536,vxlan_ids={'worker1':65536,'worker2':65537},resource_identities={'realnet_vni_v1':{'worker1':{'token':'a'*32}}})])
    restored=DeploymentState.from_dict(state.to_dict())
    assert restored.realnets[0].vxlan_ids==state.realnets[0].vxlan_ids
    assert restored.realnets[0].resource_identities==state.realnets[0].resource_identities


def test_stale_generation_is_refused_even_before_kernel_creation(tmp_path):
    registry=Registry(tmp_path/'vni');req=request();row=next(iter(registry.reserve([req],empty).values()))
    req['previous']={**row,'token':'b'*32}
    saved=(registry.directory/'registry.json').read_bytes()
    with pytest.raises(OwnershipError,match='generation'):registry.reserve([req],empty)
    assert (registry.directory/'registry.json').read_bytes()==saved


def test_lost_registry_does_not_replace_persisted_state_generation(tmp_path):
    req=request();req['previous']={'key':identity_key(req['identity']),'token':'a'*32,'vni':65536}
    registry=Registry(tmp_path/'vni')
    with pytest.raises(OwnershipError,match='generation'):registry.reserve([req],empty)
    assert not (registry.directory/'registry.json').exists()


def test_pending_reservation_protects_name_before_host_creation(tmp_path):
    registry=Registry(tmp_path/'vni');first=request('lab-one');registry.reserve([first],empty)
    second=request('lab-two');second['targets']['master']['name']=first['targets']['master']['name']
    with pytest.raises(OwnershipError,match='name is reserved'):registry.reserve([second],empty)
    assert len(registry.read()['reservations'])==1


@pytest.mark.parametrize('vni',[None,True,0,16777216,'5271'])
def test_malformed_host_vni_prevents_reservation_commit(tmp_path,vni):
    registry=Registry(tmp_path/'vni');inventory=empty({'master','worker1'})
    inventory['master']['links'].append({'ifname':'foreign','linkinfo':{'info_kind':'vxlan','info_data':{'id':vni}}})
    with pytest.raises(OwnershipError,match='inventory'):registry.reserve([request()],lambda hosts:inventory)
    assert not (registry.directory/'registry.json').exists()


def test_coordinator_release_cannot_use_another_lab_metadata(tmp_path):
    from dnlab_multinode.models.state import RealNetState
    from dnlab_multinode.services.realnet_vni import release_realnets
    registry=Registry(tmp_path/'vni');row=next(iter(registry.reserve([request('foreign')],empty).values()))
    state=RealNetState(name='access',bridge='br-test',vxlan_id=row['vni'],hosts=['master','worker1'],
                       vxlan_ids={'worker1':row['vni']},resource_identities={'realnet_vni_v1':{'worker1':row}})
    with pytest.raises(OwnershipError,match='identity'):release_realnets('lab',{},[state],directory=registry.directory)
    assert registry.read()['reservations'][row['key']]['phase']=='reserved'
