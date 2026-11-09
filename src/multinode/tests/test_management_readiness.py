"""Read-only readiness cannot be inferred from successful allocation preflight."""
from copy import deepcopy

import pytest

from dnlab_multinode.services.management_host import Worker, ManagementError
from dnlab_multinode.services.management_network_host import NetworkGuard, NetworkError
from tests.test_management_host import Host,plan,SCOPE
from tests.test_management_network_host import fixture,expected


@pytest.fixture
def kernel(tmp_path):
    host=Host();worker=Worker(plan(two=True),directory=tmp_path/'journal',run=host.run,host_context=lambda:SCOPE,kernel=host.kernel)
    return host,worker


def test_absence_is_admissible_but_not_ready_and_verification_never_allocates(kernel):
    host,worker=kernel
    assert worker.operate('preflight')['phase']=='absent'
    before=deepcopy(host.links)
    with pytest.raises(ManagementError,match='active management'):worker.operate('verify-ready')
    assert not worker.directory.exists() and host.links==before


def test_complete_generation_ready_proof_is_stable_and_readonly(kernel):
    host,worker=kernel;worker.ensure()
    before=worker.path.read_bytes();links=deepcopy(host.links);rules=deepcopy(host.rules)
    proof=worker.operate('verify-ready')
    assert proof['status']=='ready' and set(proof['proof']['resources'])==set(worker.desired())
    assert worker.operate('verify-ready')==proof
    assert worker.path.read_bytes()==before and host.links==links and host.rules==rules


@pytest.mark.parametrize('missing',['resource','flags','master','address','fdb','firewall','journal'])
def test_incomplete_runtime_resources_cannot_be_ready(kernel,missing):
    host,worker=kernel;worker.ensure();record=worker.read()
    segment=worker.plan['segments']['default'];bridge=segment['bridge'];vxlan=segment['vxlan']
    if missing=='resource':host.links.pop(vxlan);record['resources'].pop(vxlan)
    if missing=='flags':host.links[bridge]['flags']=[]
    if missing=='master':host.links[bridge].pop('master')
    if missing=='address':host.addresses[bridge]=[]
    if missing=='fdb':host.fdb[vxlan]=[]
    if missing=='firewall':host.rules['iptables']=[]
    if missing=='journal':record['phase']='applying'
    worker.save(record);before=worker.path.read_bytes()
    with pytest.raises(ManagementError):worker.operate('verify-ready')
    assert worker.path.read_bytes()==before


def test_old_active_generation_is_not_ready_for_an_expanded_desired_plan(tmp_path):
    host=Host();old=Worker(plan(),directory=tmp_path/'journal',run=host.run,host_context=lambda:SCOPE,kernel=host.kernel)
    old.ensure()
    expanded=Worker(plan(two=True),directory=old.directory,run=host.run,host_context=lambda:SCOPE,kernel=host.kernel)
    assert expanded.operate('preflight')['phase']=='active'
    before=old.path.read_bytes()
    with pytest.raises(ManagementError,match='complete active'):expanded.operate('verify-ready')
    assert old.path.read_bytes()==before
    expanded.ensure();assert expanded.operate('verify-ready')['status']=='ready'


def test_network_readiness_qualifies_original_id_and_is_readonly(fixture):
    host,worker,docker,guard=fixture
    with pytest.raises(NetworkError):guard.operate('verify-ready')
    guard.operate('ensure');before=worker.path.read_bytes();calls=deepcopy(docker.calls)
    proof=guard.operate('verify-ready')
    assert proof['status']=='ready'
    assert proof['proof']['networks']['default']['id']==worker.read()['networks']['default']['id']
    assert guard.operate('verify-ready')==proof
    assert worker.path.read_bytes()==before and docker.calls==calls


@pytest.mark.parametrize('fault',['pending','phase','id','missing','kernel'])
def test_network_readiness_refuses_incomplete_or_replaced_generation(fixture,fault):
    host,worker,docker,guard=fixture;guard.operate('ensure');record=worker.read();row=record['networks']['default']
    if fault=='pending':record['network_operation']['phase']='pending'
    if fault=='phase':row['phase']='creating'
    if fault=='id':
        original=row['id'];value=deepcopy(docker.networks[original]);docker.remove_external(original)
        value['Id']='f'*64;docker.networks[value['Id']]=value
    if fault=='missing':docker.remove_external(row['id'])
    if fault=='kernel':host.links[worker.plan['segments']['default']['bridge']]['flags']=[]
    worker.save(record);before=worker.path.read_bytes();calls=deepcopy(docker.calls)
    with pytest.raises((ManagementError,NetworkError)):guard.operate('verify-ready')
    assert worker.path.read_bytes()==before and docker.calls==calls
