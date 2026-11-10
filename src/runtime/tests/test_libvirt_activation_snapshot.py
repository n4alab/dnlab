"""Activation snapshot on fixture files with synthetic service generations."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_services import ActivationServices
from dnlab_runtime.libvirt_service_observer import ServiceGenerationObserver
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_activation_snapshot import ActivationSnapshot
from test_libvirt_install_snapshot import snapshot,fixture,request_profile
from test_libvirt_service_observer import service,install


@pytest.fixture
def activation_snapshot(snapshot,service):
    original,_,root,write,_,approved=snapshot
    source,make=service;source=deepcopy(source)
    request=dict(deepcopy(original.request),activation_policy='requisite-after-v1')
    source['request']=request;source['profile']=render_profile(**request);source['context']=original()['context']
    for item in source['items']:
        if item['spec']['kind']=='file':
            item['spec'].update(source['profile']['files'][item['spec']['path']])
            item['proof']['spec_sha256']=fingerprint(item['spec'])
    inventory=deepcopy(original()['prerequisites']['services'])
    value=dict(id='activation',installation=deepcopy(source),installation_sha256=fingerprint(source),
        items=[dict(spec=spec,phase='prepared',proof=None,nonce='b'*32) for spec in steps(source['profile'])])
    state=dict(activation=value,receipts={item['spec']['key']:None for item in value['items']});rows={}
    def generation(value,item,receipt):
        unit=item['spec']['unit']
        return ServiceGenerationObserver(source,item,value['id'],receipt,socket_path=receipt['identity']['service']['socket']['path'],
            command_sha256='c'*64,read=lambda:deepcopy(rows[unit]))
    census=ActivationServices(source,generation_observer=generation)
    provider=ActivationSnapshot(root,request,original.packages,approved,namespaces=original.namespaces,
        services=lambda:deepcopy(inventory),activation_id='activation',census=census,state_reader=lambda:deepcopy(state))
    def start_first():
        reload=value['items'][0]
        receipt=dict(activation_id='activation',nonce=reload['nonce'],spec_sha256=fingerprint(reload['spec']),identity={'synthetic_reload':True})
        reload.update(phase='confirmed',proof=receipt);state['receipts'][reload['spec']['key']]=deepcopy(receipt)
        item=value['items'][1];unit=item['spec']['unit'];_,row,proof,_,_=make(item['spec']['role'])
        row['process']['boot_id']=source['context']['boot_id'];row['process']['namespaces']=deepcopy(source['context']['namespaces'])
        row['files']={i['spec']['path']:deepcopy(i['proof']) for i in source['items'] if i['spec']['kind']=='file'}
        row['unit']['fragment_sha256']=source['profile']['files']['/etc/systemd/system/'+unit]['sha256']
        proof['identity']['service']=deepcopy(row);proof['spec_sha256']=fingerprint(item['spec'])
        item.update(phase='confirmed',proof=proof);state['receipts'][unit]=deepcopy(proof);rows[unit]=row
        inventory['units'][unit]['active_state']='active'
        inventory['processes']=[{key:deepcopy(row['process'][key]) for key in ('pid','uids','gids','groups')}]
        return row
    return provider,original,inventory,state,start_first,root,write


def test_inactive_and_acknowledged_active_snapshot(activation_snapshot):
    provider,_,inventory,_,start,_,_=activation_snapshot
    assert provider()['prerequisites']['services']['processes']==[]
    start()
    assert provider()['prerequisites']['services']==inventory


def test_original_installation_snapshot_still_requires_inactivity(activation_snapshot):
    _,original,inventory,_,start,_,_=activation_snapshot;start()
    with pytest.raises(Conflict,match='inactive'):original._services(inventory)


def test_foreign_dedicated_process_refused(activation_snapshot):
    provider,_,inventory,_,start,_,_=activation_snapshot;start()
    inventory['processes'].append(dict(pid=9999,uids=[1001]*4,gids=[1002]*4,groups=[]))
    with pytest.raises(Conflict,match='foreign, missing'):provider()


def test_static_daemon_hash_still_required(activation_snapshot):
    provider,_,_,_,_,root,write=activation_snapshot
    write('usr/sbin/libvirtd','foreign daemon preserve')
    with pytest.raises(Conflict):provider()
    assert (root/'usr/sbin/libvirtd').read_text()=='foreign daemon preserve'


def test_changed_activation_state_during_snapshot_refused(activation_snapshot,monkeypatch):
    provider,_,_,state,_,_,_=activation_snapshot;calls=[]
    def changed():
        value=deepcopy(state)
        if calls:value['activation']['id']='foreign'
        calls.append(True);return value
    monkeypatch.setattr(provider,'state_reader',changed)
    with pytest.raises(Conflict,match='activation snapshot state'):provider()


def test_replaced_daemon_generation_refused(activation_snapshot):
    provider,_,_,_,start,_,_=activation_snapshot;row=start();row['process']['start_ticks']+=1
    with pytest.raises(Conflict):provider()
