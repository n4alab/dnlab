"""Management and RealNet share a durable coordinator VNI reservation ledger."""
import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from dnlab_multinode.services.realnet_vni import Registry, identity_key, OwnershipError


def request(lab='breakout-alpha',segment='default',hosts=('master','worker1')):
    ips={h:f'192.0.2.{i+1}' for i,h in enumerate(hosts)}
    return dict(identity=[lab,'management',segment,'multipoint'],targets={h:dict(name='vm'+hashlib.sha256((lab+segment+str(i)).encode()).hexdigest()[:10],bridge='bm'+hashlib.sha256((lab+segment+str(i)).encode()).hexdigest()[:10],local=ips[h],remotes=sorted(v for k,v in ips.items() if k!=h),underlay='eth0',dstport=4789) for i,h in enumerate(hosts)})


def inventory(hosts):return {h:dict(context=dict(boot_id='boot',device=1,inode=1),links=[]) for h in hosts}


def test_retry_preserves_vni_and_token_and_new_worker_extends_same_segment(tmp_path):
    registry=Registry(tmp_path/'vni');r=request();key=identity_key(r['identity']);first=registry.reserve([r],inventory)[key]
    r['previous']=first;assert registry.reserve([r],inventory)[key]==first
    expanded=request(hosts=('master','worker1','worker2'));expanded['previous']=first
    assert registry.reserve([expanded],inventory)[key]==first
    assert len(registry.read()['reservations'][key]['targets'])==3


def test_pool_collision_and_concurrent_labs_get_distinct_vni(tmp_path,monkeypatch):
    registry=Registry(tmp_path/'vni',pool=(70000,70009));monkeypatch.setattr(Registry,'candidate',lambda *args:70000)
    def allocate(i):
        r=request(lab=f'breakout-{i}');return registry.reserve([r],inventory)[identity_key(r['identity'])]['vni']
    with ThreadPoolExecutor(max_workers=5) as pool:values=list(pool.map(allocate,range(10)))
    assert len(set(values))==10
    with pytest.raises(OwnershipError,match='exhausted'):allocate(10)


def test_management_and_realnet_cannot_reserve_same_vni(tmp_path,monkeypatch):
    registry=Registry(tmp_path/'vni',pool=(70000,70001));monkeypatch.setattr(Registry,'candidate',lambda *args:70000)
    r=request();mgmt=registry.reserve([r],inventory)
    targets={h:dict(name='vr'+str(i),bridge='br'+str(i),local=f'192.0.2.{i+1}',remote=f'192.0.2.{2-i}',underlay='eth0',dstport=14789) for i,h in enumerate(('master','worker1'))}
    realnet=registry.reserve([dict(identity=['demo','internet','worker1'],targets=targets)],inventory)
    assert next(iter(mgmt.values()))['vni']!=next(iter(realnet.values()))['vni']


@pytest.mark.parametrize('change',['remove-host','change-local','change-name','remove-peer'])
def test_existing_segment_reconfiguration_refused_before_commit(tmp_path,change):
    registry=Registry(tmp_path/'vni');r=request();key=identity_key(r['identity']);first=registry.reserve([r],inventory)[key]
    r['previous']=first
    if change=='remove-host':r=request(hosts=('master',));r['previous']=first
    elif change=='change-local':r['targets']['master']['local']='192.0.2.99';r['targets']['worker1']['remotes']=['192.0.2.99']
    elif change=='change-name':r['targets']['master']['name']='foreign'
    elif change=='remove-peer':r['targets']['master']['remotes']=[]
    before=registry.read()
    with pytest.raises(OwnershipError):registry.reserve([r],inventory)
    assert registry.read()==before


def test_failed_host_inventory_and_release_keep_reservation(tmp_path):
    registry=Registry(tmp_path/'vni');r=request();key=identity_key(r['identity']);first=registry.reserve([r],inventory)[key]
    def fail(*args):raise RuntimeError('worker unavailable')
    with pytest.raises(RuntimeError):registry.release([first],fail)
    assert registry.read()['reservations'][key]['phase']=='reserved'
    r['previous']=first
    with pytest.raises(RuntimeError):registry.reserve([r],fail)
    assert registry.read()['reservations'][key]['phase']=='reserved'
    registry.release([first],lambda:None)
    assert registry.read()['reservations'][key]['phase']=='released'


def test_observed_foreign_kernel_vni_is_skipped(tmp_path,monkeypatch):
    registry=Registry(tmp_path/'vni',pool=(70000,70001));monkeypatch.setattr(Registry,'candidate',lambda *args:70000)
    def snapshot(hosts):
        values=inventory(hosts);values['master']['links']=[dict(ifname='foreign',linkinfo=dict(info_kind='vxlan',info_data={'id':70000}))];return values
    r=request();assert registry.reserve([r],snapshot)[identity_key(r['identity'])]['vni']==70001
