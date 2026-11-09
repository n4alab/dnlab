"""Packet operation admission, durable replay and coordinator sequence."""
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import pytest
from dnlab_multinode.services.management_probe_host import Worker,validate
from dnlab_multinode.services.management_probe_exec import Execution
from dnlab_multinode.services.jumphost_host import JumphostError
from dnlab_multinode.services.management_packet_receipt import validate as validate_receipt
from dnlab_multinode.services import management_probe_runtime as transport,management_service_runtime as services,management_barrier as barrier
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_management_probe_host import fixture
from tests.test_management_probe_lifecycle import ready
from tests.test_management_prepare import setup


def profile(request):
    cfg=request['management_intent'];identity=request['identity'];attachment=request['attachment']
    value={'interface':'probe0','client_mac':identity['mac'],'client_ip':identity['ipv4'],
        'server_mac':'02:00:00:00:00:fe','server_ip':str(ipaddress.ip_interface(attachment['ipv4']).ip),
        'dns_ip':'198.19.100.2','subnet':cfg['ipv4_subnet'],'xid':123,'ipv6':None}
    if identity['ipv6']:
        value['ipv6']={'server_ip':'fe80::fe','duid':identity['duid'],'iaid':identity['iaid'],'address':identity['ipv6'],
            'dns':str(ipaddress.ip_interface(attachment['ipv6']).ip),'prefix':cfg['ipv6_subnet'],
            'solicit_xid':'123456','request_xid':'654321'}
    return value


def receipt(p):
    result={'level':'dhcp-packets','ipv4':{'reception':'AF_PACKET','client_addressless':True},'ipv6':None}
    for name,kind in (('offer',2),('ack',5)):
        result['ipv4'][name]={'offered':p['client_ip'],'server':p['server_ip'],'router':p['server_ip'],
            'dns':p['dns_ip'],'type':kind,'sent':1,'udp_checksum_status':'verified'}
    if p['ipv6']:
        six=p['ipv6'];proof={'reception':'AF_PACKET','ra':{'router_lifetime':1800,'flags':192,
            'prefixes':[{'prefix':six['prefix'],'flags':128,'preferred_lifetime':43200,'valid_lifetime':43200}]}}
        for name,kind in (('advertise',2),('reply',7)):
            proof[name]={'type':kind,'server_id':'000300010200000000fe','iaid':six['iaid'],'address':six['address'],
                'dns':six['dns'],'preferred_lifetime':43200,'valid_lifetime':43200,'t1':21600,'t2':34560,'sent':1}
        result['ipv6']=proof
    return result


def packet_worker(fixture):
    w,d,links,proof,fault=fixture
    request=deepcopy(w.request);request['packet_profile']=profile(request)
    w.__init__(request,directory=w.directory,management_directory=w.management_directory,docker=d,
        process_status=w.process_status,run=w.run,host_context=w.host_context,open_ns=w.open_ns,delete_link=w.delete_link)
    calls=[];d.packet_behavior='success'
    def emit(kind,value):
        record=w.read();op=record['packet_execution'];row={'nonce':op['nonce'],'request':transport.digest(w.request),'kind':kind,'value':value}
        with open(op['files']['output']['path'],'a') as stream:stream.write(json.dumps(row)+'\n');stream.flush()
    def start(row):
        assert w.read()['packet_phase']=='applying'
        calls.append(row['ID']);record=w.read()
        emit('birth',{'pid':100,'start':'123','namespace':record['namespace']})
    def inspect(row):
        if not row['Running'] or d.packet_behavior=='running':return
        record=w.read();raw=Path(record['packet_execution']['files']['output']['path']).read_text()
        if not any(json.loads(line)['kind']=='permit' for line in raw.splitlines()):return
        if d.packet_behavior=='failure':emit('failed',{'type':'TimeoutError','message':'fixture packet failure'});code=1
        else:
            value=receipt(request['packet_profile'])
            for stage,key in (('ipv4.offer','offer'),('ipv4.ack','ack')):emit('progress',{'stage':stage,'result':value['ipv4'][key]})
            if value['ipv6']:
                for stage,key in (('ipv6.advertise','advertise'),('ipv6.reply','reply'),('ipv6.ra','ra')):emit('progress',{'stage':stage,'result':value['ipv6'][key]})
            emit('completed',value);code=0
        row.update(Running=False,Pid=0,ExitCode=code);d.values[row['ContainerID']]['ExecIDs']=[]
    def process(current,birth):
        assert current['Pid']==100 and birth['pid']==100 and birth['start']=='123' and birth['namespace']==w.read()['namespace']
    d.on_exec_start=start;d.on_exec_inspect=inspect;w.packet_process=process
    return w,d,links,calls


def execution(w):
    record=w.read()
    return Execution(w,record).identity() if record and record.get('packet_execution') else None


def run_packets(w):
    birth=w.birth(w.read())
    if execution(w) is None:w.operate('prepare-packets',expected_birth=birth)
    return w.operate('packets',expected_birth=birth,expected_execution=execution(w))


def test_packet_operation_persists_result_and_replay_does_not_send_again(fixture):
    w,d,links,calls=packet_worker(fixture);birth=w.operate('ensure')['container_id']
    result=run_packets(w);assert result['packet_phase']=='completed' and len(calls)==1
    assert run_packets(w)['packet_result']==result['packet_result'] and len(calls)==1
    assert w.operate('cleanup',expected_birth=w.birth(w.read()),expected_execution=execution(w))['container_id']==birth and not d.values
    with pytest.raises(JumphostError):run_packets(w)
    assert len(calls)==1


def test_packet_failure_keeps_original_attempt_and_can_retry_without_new_birth(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');d.exec_lost='start'
    with pytest.raises(JumphostError,match='lost packet start'):run_packets(w)
    assert w.read()['packet_phase']=='applying' and w.read()['phase']=='active'
    d.exec_lost=None
    assert run_packets(w)['packet_phase']=='completed' and d.creates==1 and d.exec_creates==1 and d.exec_starts==1
    w.operate('cleanup',expected_birth=w.birth(w.read()),expected_execution=execution(w))


@pytest.mark.parametrize('change',['network','endpoint','container'])
def test_cached_packet_receipt_never_bypasses_live_generation_checks(fixture,change):
    w,d,links,calls=packet_worker(fixture);r=w.operate('ensure');run_packets(w)
    if change=='network':fixture[3]['network']['Id']='f'*64
    if change=='endpoint':next(v for v in links.host if v['ifname']==w.interface)['ifalias']='foreign'
    if change=='container':d.values[r['container_id']]['State']['StartedAt']='restarted'
    before=deepcopy((d.values,links.host,links.peer))
    with pytest.raises(JumphostError):run_packets(w)
    assert len(calls)==1 and before==(d.values,links.host,links.peer)


@pytest.mark.parametrize('field,bad',[('client_ip','198.18.99.4'),('client_mac','02:00:00:00:00:99'),('server_ip','198.18.99.1'),('subnet','198.18.99.0/24'),('interface','eth0'),('xid',True),('server_mac','ff:ff:ff:ff:ff:ff')])
def test_profile_drift_rejected_before_root_journal_allocation(fixture,field,bad):
    w=fixture[0];request=deepcopy(w.request);request['packet_profile']=profile(request);request['packet_profile'][field]=bad
    with pytest.raises(JumphostError):validate(request)
    assert not w.directory.exists()


@pytest.mark.parametrize('path,bad',[
 (('ipv4','ack','offered'),'198.18.99.4'),(('ipv4','ack','type'),2),
 (('ipv4','ack','dns'),'192.0.2.99'),(('ipv6','reply','iaid'),'00000000'),
 (('ipv6','reply','server_id'),'0004'),(('ipv6','reply','preferred_lifetime'),0),
 (('ipv6','ra','router_lifetime'),0),
])
def test_boundary_rejects_wrong_packet_receipts(fixture,path,bad):
    p=profile(fixture[0].request);r=receipt(p);validate_receipt(p,r)
    value=r
    for k in path[:-1]:value=value[k]
    value[path[-1]]=bad
    with pytest.raises(ValueError):validate_receipt(p,r)


@pytest.mark.parametrize('static_segment',[False,True])
def test_packet_attempts_are_sequential_and_replay_only_checks_cleanup(setup,monkeypatch,static_segment):
    calls,invoke=ready(setup,monkeypatch,static_segment=static_segment)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    previous=services.invoke
    def service(client,intent,action):
        if action=='packet_profiles':
            return {'phase':'packet-profiles','intent_fingerprint':intent['fingerprint'],
                'observation':{'observation':previous(client,intent,'observe')},'service_mutations_performed':False,
                'servers':{key:{'mac':'02:00:00:00:00:fe','link_local':None} for key in intent['packet_probe_identities']}}
        return previous(client,intent,action)
    monkeypatch.setattr(services,'invoke',service)
    def packets(client,request,action,**kwargs):
        value=invoke(client,request,action,**kwargs)
        if action=='packets':value.update(phase='active',cleanup_verified=False,packet_result=receipt(request['packet_profile']))
        return value
    monkeypatch.setattr(transport,'invoke',packets)
    result=controller.qualify_probe_packets('probe','demo',state,clients,save)
    assert result['packet_probes']['phase']=='completed' and result['phase']=='provisioning'
    assert {r['segment'] for r in result['packet_probes']['requests']}=={'default'}
    assert [(h,a) for h,a,r in calls if a!='preflight']==[(h,a) for h in ('master','worker1') for a in ('ensure','prepare-packets','packets','cleanup','verify-cleaned')]
    calls.clear();controller.qualify_probe_packets('probe','demo',state,clients,save)
    assert all(a in ('preflight','verify-cleaned') for h,a,r in calls)


@pytest.mark.parametrize('change',['unbind','host-down','peer-down'])
def test_cached_packet_receipt_requires_original_binding_and_carrier(fixture,change):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');run_packets(w)
    host=next(v for v in links.host if v['ifname']==w.interface)
    if change=='unbind':host.pop('master')
    if change=='host-down':host['flags']=[]
    if change=='peer-down':links.peer[0]['flags']=[]
    before=deepcopy((d.values,links.host,links.peer))
    with pytest.raises(JumphostError,match='active probe binding'):run_packets(w)
    assert len(calls)==1 and (d.values,links.host,links.peer)==before


def test_failed_packet_checkpoint_prevents_any_send(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');save=w.save
    def fail(record):
        if record.get('packet_phase')=='applying':raise OSError('packet journal fsync')
        save(record)
    w.save=fail
    with pytest.raises(OSError,match='fsync'):run_packets(w)
    assert not calls and 'packet_phase' not in w.read()
    w.save=save;w.operate('cleanup',expected_birth=w.birth(w.read()),expected_execution=execution(w))


@pytest.mark.parametrize('replacement',['container-id','birth-nonce'])
def test_packet_recovery_refuses_replacement_of_checkpointed_probe_birth(setup,monkeypatch,replacement):
    calls,invoke=ready(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    previous=services.invoke
    def service(client,intent,action):
        if action=='packet_profiles':
            return {'phase':'packet-profiles','intent_fingerprint':intent['fingerprint'],
                'observation':{'observation':previous(client,intent,'observe')},'service_mutations_performed':False,
                'servers':{'default':{'mac':'02:00:00:00:00:fe','link_local':None}}}
        return previous(client,intent,action)
    monkeypatch.setattr(services,'invoke',service)
    lost=[False];replacing=[False]
    def packets(client,request,action,**kwargs):
        value=invoke(client,request,action,**kwargs)
        if request['host']=='master' and replacing[0] and action!='preflight':
            proof=value['resource_proof']
            if replacement=='container-id':proof['container_id']='c'*64
            else:
                from dnlab_multinode.services.runtime_operations import digest
                proof['nonce']='4'*32
                key=digest(['management-probe-v1',request])
                proof['host']['address']='02:'+':'.join(digest([key,proof['nonce']])[i:i+2] for i in range(0,10,2))
                for side in ('host','peer'):proof[side]['ifalias']='dnlab-management-probe:'+proof['nonce']
        if action=='packets':
            value.update(phase='active',cleanup_verified=False,packet_result=receipt(request['packet_profile']))
            if not lost[0]:lost[0]=True;raise RuntimeOperationError('lost packet acknowledgement')
        return value
    monkeypatch.setattr(transport,'invoke',packets)
    with pytest.raises(RuntimeOperationError,match='lost packet acknowledgement'):
        controller.qualify_probe_packets('probe','demo',state,clients,save)
    original=deepcopy(barrier.get(store,'demo')['packet_probes'])
    assert len(original['entries'])==1
    request_id=next(iter(original['entries']))
    pinned=original['entries'][request_id]['birth']
    calls.clear();replacing[0]=True
    try:
        controller.qualify_probe_packets('probe','demo',state,clients,save)
    except RuntimeOperationError as error:
        assert 'birth' in str(error)
    else:
        current=barrier.get(store,'demo')['packet_probes']
        changed=current['entries'][request_id]['birth']
        pytest.fail('recovery accepted replacement: '+json.dumps({
            'replacement':replacement,'phase':current['phase'],
            'before':{k:pinned[k] for k in ('container_id','nonce')},
            'after':{k:changed[k] for k in ('container_id','nonce')},
            'actions':[(host,action) for host,action,request in calls]}))
    assert barrier.get(store,'demo')['packet_probes']['entries'][request_id]['birth']==pinned
    assert not any(action in ('packets','cleanup') for host,action,request in calls)
    assert not any(host=='worker1' and action=='ensure' for host,action,request in calls)


def test_bound_inspection_is_read_only_and_never_recreates(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');expected=w.birth(w.read())
    before=w.path.read_bytes(),deepcopy((d.values,links.host,links.peer)),len(d.calls)
    w.save=lambda record:pytest.fail('read-only inspect wrote journal')
    result=w.operate('inspect',expected_birth=expected)
    assert w.birth(result)==expected and w.path.read_bytes()==before[0]
    assert (d.values,links.host,links.peer)==before[1] and not calls
    assert all(method=='GET' for method,path in d.calls[before[2]:])
    assert d.creates==1


@pytest.mark.parametrize('action',['inspect','packets','cleanup'])
@pytest.mark.parametrize('change',['container_id','nonce','namespace','started_at','host','peer'])
def test_local_lock_refuses_a_changed_checkpoint_before_any_mutating_action(fixture,action,change):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');r=w.read();expected=w.birth(r)
    if change=='container_id':r[change]='c'*64
    elif change=='nonce':r[change]='4'*32
    elif change=='namespace':r[change]['inode']+=1
    elif change=='started_at':r[change]='other-start'
    else:r[change]['ifindex']+=100
    w.save(r);before=w.path.read_bytes(),deepcopy((d.values,links.host,links.peer)),len(d.calls)
    with pytest.raises(JumphostError,match='birth differs'):w.operate(action,expected_birth=expected)
    assert w.path.read_bytes()==before[0] and (d.values,links.host,links.peer)==before[1]
    assert not d.calls[before[2]:] and not calls


@pytest.mark.parametrize('action',['packets','cleanup'])
def test_bound_worker_never_accepts_omitting_the_original_birth(fixture,action):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');expected=w.birth(w.read())
    run_packets(w)
    before=w.path.read_bytes(),deepcopy((d.values,links.host,links.peer)),len(calls)
    with pytest.raises(JumphostError,match='birth required'):w.operate(action)
    assert w.path.read_bytes()==before[0] and (d.values,links.host,links.peer)==before[1] and len(calls)==before[2]


def test_failed_birth_pin_checkpoint_blocks_packets_and_cleanup(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');expected=w.birth(w.read());save=w.save
    def fail(record):
        if record.get('coordinator_birth'):raise OSError('birth pin fsync')
        save(record)
    w.save=fail;before=w.path.read_bytes(),deepcopy((d.values,links.host,links.peer))
    for action in ('prepare-packets','cleanup'):
        with pytest.raises(OSError,match='pin fsync'):w.operate(action,expected_birth=expected)
        assert w.path.read_bytes()==before[0] and (d.values,links.host,links.peer)==before[1] and not calls


def packet_controller(setup,monkeypatch):
    calls,invoke=ready(setup,monkeypatch);previous=services.invoke
    def service(client,intent,action):
        if action=='packet_profiles':
            return {'phase':'packet-profiles','intent_fingerprint':intent['fingerprint'],
                'observation':{'observation':previous(client,intent,'observe')},'service_mutations_performed':False,
                'servers':{'default':{'mac':'02:00:00:00:00:fe','link_local':None}}}
        return previous(client,intent,action)
    monkeypatch.setattr(services,'invoke',service)
    def packets(client,request,action,**kwargs):
        value=invoke(client,request,action,**kwargs)
        if action=='packets':value.update(phase='active',cleanup_verified=False,packet_result=receipt(request['packet_profile']))
        if action in ('inspect','packets','cleanup','verify-cleaned'):assert kwargs['expected_birth']==value['resource_proof']
        return value
    return calls,packets


@pytest.mark.parametrize('phase',['packets','cleanup'])
def test_lost_packet_or_cleanup_ack_recovers_same_birth_without_second_ensure(setup,monkeypatch,phase):
    calls,invoke=packet_controller(setup,monkeypatch)
    topo,state,ips,clients,runtimes,targets,store,controller,schedule,registry,events,save=setup
    failed=[]
    def lose(client,request,action,**kwargs):
        result=invoke(client,request,action,**kwargs)
        if action==phase and not failed:failed.append(True);raise RuntimeOperationError('lost ack')
        return result
    monkeypatch.setattr(transport,'invoke',lose)
    with pytest.raises(RuntimeOperationError,match='lost ack'):
        controller.qualify_probe_packets('probe','demo',state,clients,save)
    original=deepcopy(barrier.get(store,'demo')['packet_probes']);assert len(original['entries'])==1
    rid=next(iter(original['entries']));birth=original['entries'][rid]['birth']
    assert not any(h=='worker1' and a=='ensure' for h,a,r in calls)
    calls.clear();result=controller.qualify_probe_packets('probe','demo',state,clients,save)
    assert result['packet_probes']['phase']=='completed' and result['phase']=='provisioning'
    assert result['packet_probes']['entries'][rid]['birth']==birth
    assert not any(h=='master' and a=='ensure' for h,a,r in calls)
    assert any(h=='master' and a=='inspect' for h,a,r in calls)==(phase=='packets')


@pytest.mark.parametrize('action',['inspect','packets','cleanup','verify-cleaned'])
def test_transport_carries_expected_birth_and_rejects_another_receipt(fixture,action):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');expected=w.birth(w.read());w.operate('prepare-packets',expected_birth=expected);expected_exec=execution(w);envelopes=[]
    class Client:
        changed=False
        def run_input(self,command,payload,**kwargs):
            envelope=json.loads(payload)['request'];envelopes.append(envelope)
            assert envelope['action']==action and envelope['expected_birth']==expected and envelope['expected_execution']==expected_exec
            value={'phase':'cleaned' if action in ('cleanup','verify-cleaned') else 'active',
                'request_fingerprint':transport.digest(w.request),'cleanup_verified':action in ('cleanup','verify-cleaned'),
                'resource_proof':deepcopy(expected),'execution':expected_exec,'execution_status':{'exit_verified':True,'exit_code':0}}
            if action=='packets':value['packet_result']=receipt(w.request['packet_profile'])
            if self.changed:value['resource_proof']['container_id']='f'*64
            return json.dumps(value)
    client=Client();assert transport.invoke(client,w.request,action,expected_birth=expected,expected_execution=expected_exec)['resource_proof']==expected
    client.changed=True
    with pytest.raises(RuntimeOperationError,match='birth differs'):
        transport.invoke(client,w.request,action,expected_birth=expected,expected_execution=expected_exec)
    assert len(envelopes)==2


def test_missing_expected_birth_refuses_packets_before_transport(fixture):
    class Client:
        def run_input(self,*args,**kwargs):pytest.fail('unbound packets reached remote transport')
    with pytest.raises(RuntimeOperationError,match='birth required'):
        transport.invoke(Client(),fixture[0].request,'packets')


def test_inspection_of_missing_attempt_never_creates_a_journal(fixture):
    w=fixture[0]
    with pytest.raises(JumphostError,match='journal required'):w.operate('inspect')
    assert not w.directory.exists() and not fixture[1].calls


def test_unbound_fixture_cleanup_never_pins_a_partial_birth(fixture):
    w,d,links,proof,fault=fixture;d.lost='create'
    with pytest.raises(JumphostError):w.operate('ensure')
    record=w.read();before=w.path.read_bytes(),deepcopy(d.values)
    with pytest.raises(JumphostError,match='complete expected'):
        w.operate('cleanup',expected_birth=w.birth(record))
    assert w.path.read_bytes()==before[0] and d.values==before[1]
    d.lost=None
    assert w.operate('cleanup')['phase']=='cleaned' and not d.values


@pytest.mark.parametrize('action',['packets','cleanup'])
def test_uncertain_packet_process_blocks_retry_and_cleanup_until_exit_is_qualified(fixture,action,monkeypatch):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');d.packet_behavior='running'
    monkeypatch.setattr(Execution,'WAIT_SECONDS',0)
    with pytest.raises(JumphostError,match='remains running'):run_packets(w)
    assert w.read()['packet_phase']=='applying' and len(calls)==1
    before=deepcopy((d.values,links.host,links.peer));identity=execution(w)
    with pytest.raises(JumphostError):
        w.operate(action,expected_birth=w.birth(w.read()),expected_execution=identity)
    assert len(calls)==1 and d.exec_creates==d.exec_starts==1 and (d.values,links.host,links.peer)==before
