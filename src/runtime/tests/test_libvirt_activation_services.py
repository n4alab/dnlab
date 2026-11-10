"""Synthetic systemd/process/socket acknowledgements; no host observations."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_services import ActivationServices
from dnlab_runtime.libvirt_service_observer import ServiceGenerationObserver
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def progressive(service):
    installation,make=service;items=[];receipts={};observed={};command='c'*64
    for index,spec in enumerate(steps(installation['profile'])):
        item=dict(spec=spec,nonce='b'*32,phase='confirmed',proof=None)
        if spec['kind']=='reload':
            proof=dict(activation_id='activation',nonce=item['nonce'],spec_sha256=fingerprint(spec),identity={'synthetic_reload':True})
        else:
            _,row,proof,_,path=make(spec['role'])
            pid=1234+index;row['unit']['pid']=pid;row['process']['pid']=pid;row['socket']['peer_pid']=pid
            proof['identity']['service']=deepcopy(row);observed[spec['unit']]=row
        item['proof']=deepcopy(proof);items.append(item);receipts[spec['key']]=proof
    value=dict(id='activation',installation=deepcopy(installation),installation_sha256=fingerprint(installation),items=items)
    names=installation['profile']['service_order']+installation['profile']['forbidden_vendor_activation']
    inventory=dict(units={name:dict(active_state='inactive',job_id=0) for name in names},
        dedicated_uid=installation['profile']['session']['uid'],processes=[])
    for item in items[1:]:
        unit=item['spec']['unit'];row=observed[unit]
        inventory['units'][unit]['active_state']='active'
        inventory['processes'].append({key:deepcopy(row['process'][key]) for key in ('pid','uids','gids','groups')})
    def generation(value,item,receipt):
        unit=item['spec']['unit'];path=receipt['identity']['service']['socket']['path']
        return ServiceGenerationObserver(installation,item,value['id'],receipt,socket_path=path,
            command_sha256=command,read=lambda:deepcopy(observed[unit]))
    validator=ActivationServices(installation,generation_observer=generation)
    return validator,value,inventory,receipts,observed


@pytest.mark.parametrize('completed',range(5))
def test_only_acknowledged_prefix_is_accepted(progressive,completed):
    validator,value,inventory,receipts,_=progressive
    for item in value['items'][completed:]:
        item.update(phase='prepared',proof=None);receipts[item['spec']['key']]=None
        if item['spec']['kind']=='start':inventory['units'][item['spec']['unit']]['active_state']='inactive'
    active={item['proof']['identity']['service']['process']['pid'] for item in value['items'][:completed] if item['spec']['kind']=='start'}
    inventory['processes']=[row for row in inventory['processes'] if row['pid'] in active]
    assert validator.validate(value,inventory,receipts)['inventory_sha256']==fingerprint(inventory)


def test_requested_original_completion_is_accepted_without_confirmed_checkpoint(progressive):
    validator,value,inventory,receipts,_=progressive
    value['items'][-1].update(phase='requested',proof=None)
    assert validator.validate(value,inventory,receipts)['receipts_sha256']==fingerprint(receipts)


@pytest.mark.parametrize('fault',['foreign_process','missing_process','credentials','vendor_active','job','generation','missing_ack','duplicate_pid'])
def test_foreign_or_incomplete_inventory_is_refused(progressive,fault):
    validator,value,inventory,receipts,observed=progressive
    first=value['items'][1]['spec']['unit']
    if fault=='foreign_process':inventory['processes'].append(dict(pid=9999,uids=[1001]*4,gids=[1002]*4,groups=[]))
    elif fault=='missing_process':inventory['processes'].pop()
    elif fault=='credentials':inventory['processes'][0]['uids']=[0]*4
    elif fault=='vendor_active':inventory['units'][validator.installation['profile']['forbidden_vendor_activation'][0]]['active_state']='active'
    elif fault=='job':inventory['units'][first]['job_id']=1
    elif fault=='generation':observed[first]['process']['start_ticks']+=1
    elif fault=='missing_ack':receipts[first]=None
    else:inventory['processes'].append(deepcopy(inventory['processes'][0]))
    with pytest.raises(Conflict):validator.validate(value,inventory,receipts)


def test_generation_rechecked_after_census(progressive,monkeypatch):
    validator,value,inventory,receipts,_=progressive;factory=validator.generation_observer
    def changing(*args):
        observer=factory(*args);calls=[]
        def read():
            row=observer();calls.append(True)
            if len(calls)>1:row['process']['start_ticks']+=1
            return row
        return read
    monkeypatch.setattr(validator,'generation_observer',changing)
    with pytest.raises(Conflict,match='changed during census'):validator.validate(value,inventory,receipts)
