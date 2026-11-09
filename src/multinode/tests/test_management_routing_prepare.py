"""Pair admission/recovery must preserve peers, generations and the fence."""
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_multinode.controllers.management_routing_prepare import qualify
from dnlab_multinode.services import management_barrier as barrier,netsetup
from dnlab_multinode.services import management_probe_runtime as probes,management_service_runtime as services
from dnlab_multinode.services.management_packet_receipt import routing_profile
from dnlab_multinode.services.runtime_operations import RuntimeOperationError,digest
from tests.test_management_routing_probe import profile,result


@pytest.fixture
def environment(monkeypatch):
    observation={'phase':'observed','jumphost':{'container_id':'a'*64}}
    model={'networks':{}};identities={};attachments={};servers={};proof={};hosts={}
    for side,segment in enumerate(('default','blue')):
        p=profile(side);cfg={'ipv4_gw':p['server_ip'],'ipv4_subnet':f'198.19.{233+side}.0/24',
            'ipv6_gw':p['server_ipv6'],'ipv6_subnet':f'2001:db8:{233+side}::/64'}
        model['networks'][segment]=cfg
        identities[segment]={'owner':'@management-probe:'+segment,'mac':p['client_mac'],
            'ipv4':p['addresses']['4'],'ipv6':p['addresses']['6'],'duid':'00:04:'+':'.join(['aa']*16),'iaid':'12345678'}
        attachments[segment]={'attachment':{'segment':segment,'interface':'eth1' if side==0 else 'jmblue',
            'ipv4':cfg['ipv4_gw']+'/24','ipv6':cfg['ipv6_gw']+'/64'}}
        servers[segment]={'mac':p['server_mac'],'link_local':p['server_link_local']}
    for host in ('master','worker1'):
        hosts[host]={'segments':{key:{'network':deepcopy(cfg)} for key,cfg in model['networks'].items()}}
        proof[host]={'networks':{'proof':{'networks':{key:{'id':digest([host,key]),'nonce':digest([host,key,'nonce'])[:32]} for key in model['networks']}}}}
    bundle={'lab':'demo','fingerprint':'f'*64,'management_plan':model,'packet_probe_identities':identities,
        'attachments':attachments,'jumphost':{'image':'sha256:'+'a'*64}}
    row={'phase':'provisioning','barrier_id':'1'*32,'plan':{'services':bundle,'management_generation':'2'*32,'hosts':hosts},
        'targets':{h:{} for h in hosts},'services':{'observation':{'services':observation}}}
    database={'row':deepcopy(row)};calls=[];world={};saves=[];fault={'action':None,'used':False,'replace':False}
    driver=SimpleNamespace(provisioning=lambda *a:nullcontext(),original=lambda *a:deepcopy(database['row']),
        remote=lambda *args:None)
    store=SimpleNamespace(transaction=lambda:nullcontext())
    controller=SimpleNamespace(driver=driver,store=store,observe_services=lambda *args:None)
    state=SimpleNamespace(management_plan=deepcopy(model))
    monkeypatch.setattr(barrier,'put',lambda store,lab,value:database.update(row=deepcopy(value)))
    monkeypatch.setattr(netsetup,'verify_management_ready',lambda *a:deepcopy(proof))
    def service(client,intent,action):
        if action=='packet_profiles':return {'observation':{'observation':deepcopy(observation)},'servers':deepcopy(servers)}
        assert action=='routing_snapshot'
        return {'observation':deepcopy(observation),'validation':{'status':'accepted'},'service_mutations_performed':False}
    monkeypatch.setattr(services,'invoke',service)
    def invoke(client,request,action,*,expected_birth=None,expected_execution=None):
        routing_profile(request['packet_profile'],request)
        calls.append((request['request_id'],action))
        if action=='preflight':return {}
        key=request['request_id'];own=world.get(key)
        if action=='ensure':
            assert own is None
            own={'birth':{'container_id':digest([key,'cid']),'nonce':'3'*32},'execution':None,'creates':1,'starts':0,'packets':0,'cleaned':False}
            world[key]=own
        else:
            assert own is not None
            if fault['replace']:raise RuntimeOperationError('original birth changed')
            assert expected_birth==own['birth']
            if expected_execution is not None:assert expected_execution==own['execution']
        if action=='prepare-packets' and own['execution'] is None:
            request_key=digest(['management-probe-v1',request])
            own['execution']={'id':digest([key,'exec']),'container_id':own['birth']['container_id'],
                'nonce':digest(['probe-exec-v1',request_key,'3'*32])[:32],'command_sha256':'a'*64}
        if action=='start-packets':
            committed=database['row']['routing_probes']
            pair=next(pair for pair in committed['pairs'] if request in pair['requests'])
            assert all(committed['entries'][r['request_id']].get('execution') for r in pair['requests'])
            own['starts']=1
        if action=='packets':own['packets']=1
        if action=='cleanup':
            pair=next(p for p in database['row']['routing_probes']['pairs'] if request in p['requests'])
            assert all(database['row']['routing_probes']['entries'][r['request_id']]['phase'] in ('packets-completed','cleanup_pending','cleaned') for r in pair['requests'])
            own['cleaned']=True
        if action=='verify-cleaned':assert own['cleaned']
        response={'resource_proof':dict(own['birth'],nonce='3'*32),'execution':deepcopy(own['execution']),
            'cleanup_verified':own['cleaned'],'phase':'cleaned' if own['cleaned'] else 'active'}
        if action=='packets':response['packet_result']=result(request['packet_profile'])
        if action==fault['action'] and not fault['used']:
            fault['used']=True;raise RuntimeOperationError('lost '+action)
        return response
    monkeypatch.setattr(probes,'invoke',invoke)
    def checkpoint():saves.append(deepcopy(database['row']))
    def run():return qualify(controller,'prepare','demo',state,{h:object() for h in hosts},checkpoint)
    return SimpleNamespace(run=run,database=database,calls=calls,world=world,fault=fault,servers=servers)


def test_all_host_pairs_complete_before_cleanup_and_replay_is_readonly(environment):
    e=environment;r=e.run()['routing_probes']
    assert r['phase']=='completed' and r['packet_forwarding_verified'] is True
    assert len(r['pairs'])==4 and len(r['entries'])==8
    assert all(v['cleaned'] and v['starts']==v['packets']==v['creates']==1 for v in e.world.values())
    e.calls.clear();assert e.run()['routing_probes']==r
    assert {action for key,action in e.calls}=={'verify-cleaned'}
    assert e.database['row']['phase']=='provisioning'


@pytest.mark.parametrize('action',['prepare-packets','start-packets','packets','cleanup'])
def test_lost_ack_recovers_original_pair_before_next_pair(environment,action):
    e=environment;e.fault['action']=action
    with pytest.raises(RuntimeOperationError,match='lost'):e.run()
    first=set(e.world);assert len(first)<=2
    e.calls.clear();r=e.run()['routing_probes']
    assert r['phase']=='completed' and all(v['creates']==1 and v['starts']==1 for v in e.world.values())
    assert not any(key in first and action=='ensure' for key,action in e.calls)


def test_replaced_peer_blocks_recovery_and_no_next_pair_is_allocated(environment):
    e=environment;e.fault['action']='start-packets'
    with pytest.raises(RuntimeOperationError):e.run()
    first=set(e.world);e.fault['replace']=True
    with pytest.raises(RuntimeOperationError,match='birth changed'):e.run()
    assert set(e.world)==first and e.database['row']['phase']=='provisioning'
    assert not any(v['cleaned'] for v in e.world.values())


def test_changed_router_profile_rejected_before_allocating_another_pair(environment):
    e=environment;e.fault['action']='start-packets'
    with pytest.raises(RuntimeOperationError):e.run()
    first=set(e.world);e.servers['blue']['mac']='02:00:00:00:aa:aa'
    with pytest.raises(RuntimeOperationError,match='generation changed'):e.run()
    assert set(e.world)==first and not any(v['cleaned'] for v in e.world.values())
