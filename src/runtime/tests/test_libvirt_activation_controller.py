"""Real activation/command/ack journals with fully synthetic service providers."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation_controller import ActivationController,resource_digest
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def controller(service,install):
    source,make=service;source=deepcopy(source);source['request']['activation_policy']='requisite-after-v1'
    source['profile']=render_profile(**source['request'])
    for item in source['items']:
        if item['spec']['kind']=='file':
            item['spec'].update(source['profile']['files'][item['spec']['path']]);item['proof']['spec_sha256']=fingerprint(item['spec'])
    state=dict(calls=[],references={},events={},workers={},monitor_valid=True,resources_valid=True,domains=[],lost=None,conflict_after=None)
    class Monitor:
        def verify(self,reference,request):
            return state['monitor_valid'] and reference==state['references'].get(request['spec']['unit']) and reference['request_sha256']==fingerprint(request)
        def read_original(self,reference,request):
            return dict(request_sha256=fingerprint(request),monitor_sha256=fingerprint(reference),service=deepcopy(state['events'][request['spec']['unit']]))
    class Runner:
        def arm(self,command):
            token=format(len(state['workers'])+1,'032x')
            reference=dict(token=token,command_sha256=fingerprint(command),process_record=dict(boot_id=source['context']['boot_id'],
                pid=5000+len(state['workers']),start_ticks=123,uid=0,gid=0,executable_sha256='d'*64,
                namespace_sha256=fingerprint(source['context']['namespaces'])))
            state['workers'][token]=dict(reference=reference,command=deepcopy(command),outcome=None,released=False)
            return deepcopy(reference)
        def verify(self,reference,command):
            worker=state['workers'][reference['token']];return worker['reference']==reference and worker['command']==command
        def release(self,reference):
            worker=state['workers'][reference['token']];assert not worker['released'];worker['released']=True
            command=worker['command'];key='manager-reload' if command['argv'][1]=='daemon-reload' else command['argv'][-1]
            state['calls'].append(key)
            if key!='manager-reload':
                role=key.removeprefix('dnlab-').removesuffix('.service');_,row,_,_,_=make(role)
                pid=6000+len(state['events']);row['unit']['pid']=pid;row['process']['pid']=pid;row['socket']['peer_pid']=pid
                row['files']={i['spec']['path']:deepcopy(i['proof']) for i in source['items'] if i['spec']['kind']=='file'}
                row['unit']['fragment_sha256']=source['profile']['files']['/etc/systemd/system/'+key]['sha256']
                state['events'][key]=row
            worker['outcome']=dict(reference=deepcopy(reference),exit_code=0,stdout='',stderr='')
            if state['conflict_after']==key:state['resources_valid']=False
            if state['lost']==key:raise OSError('synthetic original release reply lost')
        def outcome(self,reference):return deepcopy(state['workers'][reference['token']]['outcome'])
        def completed_outcome(self,reference):return self.outcome(reference)
    def inventory():
        names=source['profile']['service_order']+source['profile']['forbidden_vendor_activation']
        units={name:dict(active_state='active' if name in state['events'] else 'inactive',job_id=0) for name in names}
        processes=[{key:deepcopy(row['process'][key]) for key in ('pid','uids','gids','groups')} for row in state['events'].values()]
        return dict(units=units,dedicated_uid=source['profile']['session']['uid'],processes=processes)
    def resources(value,receipts):
        return dict(qualified=True,installation_sha256=fingerprint(source),context_sha256=fingerprint(source['context']),
            resources_sha256=resource_digest(source) if state['resources_valid'] else '0'*64)
    def empty(value,receipts):return dict(installation_sha256=fingerprint(source),domains=deepcopy(state['domains']),
        service_proofs_sha256=fingerprint([receipts[item['spec']['key']] for item in value['items']]))
    from dnlab_runtime.libvirt_activation import steps
    agreement=dict(operation_id='activation',context=deepcopy(source['context']),targets=[spec['key'] for spec in steps(source['profile'])],nonce='a'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    driver=ActivationController(install[0].journal,source,operation='activation',window=window,
        binary=dict(path='/usr/bin/systemctl',sha256='b'*64),runner=Runner(),source_reader=lambda:deepcopy(source),
        monitor=Monitor(),resources=resources,inventory=inventory,empty=empty)
    reference=driver.prepare();references={}
    for index,item in enumerate(reference['items']):
        if item['spec']['kind']=='start':
            request=driver.monitor_request(reference,item)
            references[item['spec']['unit']]=dict(kind='original-activation-monitor-v1',token=format(index+1,'032x'),
                request_sha256=fingerprint(request),context_sha256=fingerprint(source['context']))
    state['references']=deepcopy(references)
    return driver,reference,references,state,agreement


def test_ordered_activation_and_replay_without_new_commands(controller):
    driver,reference,references,state,window=controller
    assert state['calls']==[];driver.bind_monitors(references)
    result=driver.apply_original(reference)
    assert result['phase']=='ready_empty'
    assert state['calls']==['manager-reload']+driver.source['profile']['service_order']
    window['nonce']='0'*32
    assert driver.apply_original(reference)==result and len(state['calls'])==4
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_activation_acknowledgements').fetchone()[0]==3


def test_complete_monitor_binding_required_before_first_command(controller):
    driver,reference,_,state,_=controller
    with pytest.raises(Conflict,match='monitor binding required'):driver.apply_original(reference)
    assert state['calls']==[]


def test_lost_start_reply_recovery_does_not_advance_later_steps(controller):
    driver,reference,references,state,_=controller;driver.bind_monitors(references)
    first=driver.source['profile']['service_order'][0];state['lost']=first
    with pytest.raises(OSError):driver.apply_original(reference)
    assert state['calls']==['manager-reload',first]
    recovered=driver.recover_original(reference)
    assert recovered['items'][1]['phase']=='requested' and len(state['calls'])==2
    assert driver.apply_original(reference)['phase']=='ready_empty' and len(state['calls'])==4
    assert len(set(state['calls']))==4


def test_resource_conflict_after_start_keeps_pending_and_same_monitor(controller):
    driver,reference,references,state,_=controller;driver.bind_monitors(references)
    first=driver.source['profile']['service_order'][0];state['conflict_after']=first
    with pytest.raises(Conflict):driver.apply_original(reference)
    assert state['calls']==['manager-reload',first]
    state['resources_valid']=True
    driver.recover_original(reference)
    assert len(state['calls'])==2
    assert driver.apply_original(reference)['phase']=='ready_empty' and len(state['calls'])==4
    assert driver._monitors(driver.driver.read('activation'))==references


def test_foreign_monitor_or_resource_blocks_before_commands(controller):
    driver,reference,references,state,_=controller;driver.bind_monitors(references);state['monitor_valid']=False
    with pytest.raises(Conflict):driver.apply_original(reference)
    assert state['calls']==[]


def test_foreign_domain_never_becomes_ready_and_does_not_restart_services(controller):
    driver,reference,references,state,_=controller;driver.bind_monitors(references);state['domains']=['foreign']
    with pytest.raises(Conflict,match='empty session'):driver.apply_original(reference)
    assert len(state['calls'])==4
    state['domains']=[]
    assert driver.apply_original(reference)['phase']=='ready_empty' and len(state['calls'])==4
