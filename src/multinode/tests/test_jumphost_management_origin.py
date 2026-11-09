"""Jumphost attachment admission is bound to the network creator journal."""
import copy
import json

import pytest

from tests.test_jumphost_host import world
from dnlab_multinode.services.jumphost_host import JumphostError


def mutate_origin(environment, callback):
    value=json.loads(environment.origin_path.read_text());callback(value)
    environment.origin_path.write_text(json.dumps(value));environment.origin_path.chmod(0o600)


def mutations(environment):
    return [v for v in environment.calls if v[:2] in (['docker','create'],['docker','start'],['docker','kill'],['docker','rm'])
            or v[:3]==['ip','link','add'] or v[:1]==['nsenter'] or v[:1]==['delete-index']]


@pytest.mark.parametrize('difference',['id','nonce','tenant','gateway','subnet','driver','ipv6','bridge-proof',
    'vrf-proof','vrf-table','context','pending','network-pending','operation-pending','missing','missing-intent','desired'])
def test_invalid_network_origin_refused_before_jumphost_birth(world,difference):
    env,worker=world
    if difference=='id':env.management['Id']='d'*64
    if difference=='nonce':env.management['Labels']['org.dnlab.management.creator']='d'*32
    if difference=='tenant':env.management['IPAM']['Options']['dnlab.tenant']='foreign'
    if difference=='gateway':env.management['IPAM']['Config'][0]['Gateway']='198.18.0.2'
    if difference=='subnet':env.management['IPAM']['Config'][0]['Subnet']='198.18.9.0/24'
    if difference=='driver':env.management['IPAM']['Driver']='default'
    if difference=='ipv6':env.management['EnableIPv6']=True
    if difference=='bridge-proof':mutate_origin(env,lambda r:r['resources']['br-mgmt']['identity'].update(ifindex=999))
    if difference=='vrf-proof':mutate_origin(env,lambda r:r['resources']['vrf-test']['identity'].update(ifindex=999))
    if difference=='vrf-table':env.host[0]['linkinfo']['info_data']['table']=999
    if difference=='context':mutate_origin(env,lambda r:r['context'].update(inode=999))
    if difference=='pending':mutate_origin(env,lambda r:r.update(phase='applying'))
    if difference=='network-pending':mutate_origin(env,lambda r:r['networks']['default'].update(phase='creating'))
    if difference=='operation-pending':mutate_origin(env,lambda r:r['network_operation'].update(phase='pending'))
    if difference=='missing':env.origin_path.unlink()
    if difference=='missing-intent':mutate_origin(env,lambda r:r['networks'].clear())
    if difference=='desired':
        env.cfg['management_intent']=copy.deepcopy(env.origin['networks']['default']['expected'])
        env.cfg['management_intent']['host_count']=2
    before=copy.deepcopy((env.host,env.management))
    with pytest.raises((JumphostError,OSError)):worker.operate('ensure',env.cfg)
    assert not mutations(env) and not worker.path.exists()
    assert (env.host,env.management)==before


@pytest.mark.parametrize('action',['read','ensure','recover','preflight-delete','delete'])
def test_replaced_network_refused_on_all_existing_lifecycle_paths(world,action):
    env,worker=world;worker.operate('ensure',env.cfg)
    original=worker.path.read_bytes();env.calls.clear();env.management['Id']='d'*64
    with pytest.raises(JumphostError):worker.operate(action,env.cfg if action=='ensure' else None)
    assert not mutations(env)
    # Recovery/delete retain the error and original generation, rather than
    # adopting the new Docker ID or claiming a completed teardown.
    record=worker.read()
    assert record['management_network']['network']['Id']=='c'*64
    assert record['phase']!='cleaned'
    if action in ('read','ensure','preflight-delete'):assert worker.path.read_bytes()==original


def test_lost_birth_ack_does_not_authorize_recovery_on_changed_origin(world):
    env,worker=world;env.lost='create'
    with pytest.raises(JumphostError):worker.operate('ensure',env.cfg)
    env.lost=None;env.calls.clear()
    mutate_origin(env,lambda r:r['networks']['default'].update(nonce='d'*32))
    env.management['Labels']['org.dnlab.management.creator']='d'*32
    with pytest.raises(JumphostError):worker.operate('recover')
    assert not mutations(env) and worker.read()['phase']=='recovery_required'


def test_same_network_proof_is_persisted_before_container_allocation(world):
    env,worker=world
    def before(args):
        if args[:2]==['docker','create']:
            proof=worker.read()['management_network']
            assert proof['network']['Id']==env.origin['networks']['default']['id']
            assert proof['origin']['network_nonce']==env.origin['networks']['default']['nonce']
    env.before=before
    original=worker.operate('ensure',env.cfg)
    assert worker.operate('ensure',env.cfg)==original


def test_extra_completed_segment_does_not_change_original_attachment_proof(world):
    env,worker=world;first=worker.operate('ensure',env.cfg)
    mutate_origin(env,lambda r:r['networks'].update(blue={'phase':'active','id':'d'*64}))
    assert worker.operate('read')==first
