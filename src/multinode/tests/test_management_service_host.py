"""Compose real helper journals with existing stateful Docker/kernel fixtures."""
from copy import deepcopy
import json
import pytest
from dnlab_multinode.services.management_service_host import Services
from dnlab_multinode.services.jumphost_host import JumphostError,digest
from dnlab_multinode.services.jumphost_network_host import Worker as NetworkWorker
from tests.test_jumphost_host import World,config as jump_config
from tests.test_dns_host import DNSWorld,config as dns_config
from tests.test_jumphost_network_guard import Environment,CONFIG,CONTEXT


@pytest.fixture
def runtime(tmp_path):
    jc=jump_config();dc=dns_config();jc['image']=dc['image']='sha256:'+'b'*64
    network={('name' if k=='network' else k):v for k,v in CONFIG.items()}
    jc['network']=deepcopy(network);dc['network']=deepcopy(network)
    jc['ip']='198.19.245.3';dc['ip']='198.19.245.2'
    jw=World(jc);dw=DNSWorld();dw.cfg.update(dc)
    class Env(Environment):
        def create(self,payload):
            result=super().create(payload)
            jw.network=deepcopy(self.value);dw.network=deepcopy(self.value)
            return result
    # The original single-helper fixture hardcodes the external key 'shared'.
    # Preserve its Docker behavior while exposing this composed intent's name.
    for world in (jw,dw):
        original=world.run
        def run(argv,_world=world,_original=original,**kwargs):
            selected=list(argv)
            if selected[:3]==['docker','network','inspect'] and selected[3]==CONFIG['network']:selected[3]='shared'
            try:return _original(selected,**kwargs)
            finally:
                if selected[:2]==['docker','create']:
                    for value in _world.values.values():
                        endpoints=value['NetworkSettings']['Networks']
                        if 'shared' in endpoints:endpoints[CONFIG['network']]=endpoints.pop('shared')
        world.run=run
    env=Env();nw=NetworkWorker(CONFIG,directory=tmp_path/'external',docker=env,run=env.run,host_context=lambda:CONTEXT)
    jump=jw.worker(tmp_path/'jump');dns=dw.worker(tmp_path/'dns')
    bundle={'schema_version':1,'lab':jc['lab'],'host':'master','jumphost':jc,
        'dns':{'config':dc,'content':'198.18.0.11 r1\n'},
        'attachments':{'default':{'attachment':deepcopy(jc['attachment'])}}}
    bundle['fingerprint']=digest(bundle)
    worker=Services(bundle,jump_directory='',dns_directory='',network_directory='',management_directory='',jump=jump,dns=dns,network=nw)
    return worker,jw,dw,env,jump,dns,nw


def test_full_materialization_and_replay_create_once_with_original_nonces(runtime):
    worker,jw,dw,env,jump,dns,nw=runtime
    assert worker.preflight()['phase']=='preflight'
    assert not jump.path.exists() and not dns.path.exists() and not nw.path.exists()
    first=worker.apply();before=(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes())
    assert first['phase']=='materialized' and first['functional_readiness_verified'] is False
    assert worker.apply()==first
    assert before==(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes())
    assert len(env.creates)==1
    assert sum(v[:2]==['docker','create'] for v in jw.calls)==1
    assert sum(v[:2]==['docker','create'] for v in dw.calls)==1


@pytest.mark.parametrize('service,failure',[('jump','create'),('jump','start'),('dns','create'),('dns','start')])
def test_partial_service_birth_recovers_without_replacement(runtime,service,failure):
    worker,jw,dw,env,jump,dns,nw=runtime
    world=jw if service=='jump' else dw;world.lost=failure
    with pytest.raises(JumphostError):worker.apply()
    original=(jump.read() or {}).get('nonce'),(dns.read() or {}).get('nonce')
    world.lost=None
    result=worker.apply()
    assert result['phase']=='materialized'
    if original[0]:assert jump.read()['nonce']==original[0]
    if original[1]:assert dns.read()['nonce']==original[1]
    assert len(env.creates)==1
    assert sum(v[:2]==['docker','create'] for v in jw.calls)==1
    assert sum(v[:2]==['docker','create'] for v in dw.calls)==1


def test_foreign_service_refused_before_shared_network_allocation(runtime):
    worker,jw,dw,env,jump,dns,nw=runtime
    dw.values['f'*64]={'Id':'f'*64,'Name':'/'+dw.cfg['name']}
    with pytest.raises(JumphostError,match='foreign service'):worker.apply()
    assert not env.creates and not jump.path.exists() and not dns.path.exists()


def test_replaced_service_is_preserved_and_other_helper_not_recreated(runtime):
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    value=dw.values.pop('1'*64);value['Id']='f'*64;dw.values['f'*64]=value
    creates=len(env.creates);before=deepcopy((jw.values,dw.values))
    with pytest.raises(JumphostError,match='generation replaced'):worker.apply()
    assert (jw.values,dw.values)==before and len(env.creates)==creates


def test_bound_recovery_refuses_configuration_drift(runtime):
    worker,jw,dw,env,jump,dns,nw=runtime
    dw.lost='start'
    with pytest.raises(JumphostError):worker.apply()
    dc=deepcopy(worker.intent['dns']['config']);dc['upstream']=['203.0.113.53']
    before=len(dw.calls)
    with pytest.raises(JumphostError,match='recovery original DNS'):dns.operate('recover',dc,worker.intent['dns']['content'])
    assert len(dw.calls)==before


def test_observation_requires_materialization_then_requalifies_without_writes(runtime):
    worker,jw,dw,env,jump,dns,nw=runtime
    with pytest.raises(JumphostError,match='complete active'):worker.observe()
    assert not jump.path.exists() and not dns.path.exists() and not nw.path.exists()
    receipt=worker.apply()
    before=(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes(),deepcopy(jw.values),deepcopy(dw.values),len(env.creates))
    jw.calls.clear();dw.calls.clear()
    observed=worker.observe()
    assert observed['phase']=='observed'
    assert observed['functional_readiness_verified'] is False and observed['mutations_performed'] is False
    for key in ('jumphost','dns','external_network_id'):assert observed[key]==receipt[key]
    assert observed['management_networks']=={'default':'c'*64}
    assert before==(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes(),jw.values,dw.values,len(env.creates))
    assert all(v[:2] not in (['docker','create'],['docker','start'],['docker','kill'],['docker','rm']) for v in jw.calls+dw.calls)


@pytest.mark.parametrize('fault',['jump-pending','dns-pending','external-pending','dhcp-pending','inventory-pending','dns-file-pending','missing-attachment','stopped','replaced','dns-asset'])
def test_observation_refuses_incomplete_or_changed_materialization(runtime,fault):
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    if fault in ('jump-pending','dhcp-pending','inventory-pending'):
        row=jump.read()
        if fault=='jump-pending':row['phase']='recovery_required'
        else:row['dhcp_operation' if fault=='dhcp-pending' else 'inventory_operation']={'id':'pending'}
        jump.save(row)
    elif fault in ('dns-pending','dns-file-pending'):
        row=dns.read()
        if fault=='dns-pending':row['phase']='reload_pending'
        else:row['file_operation']={'id':'pending'}
        dns.save(row)
    elif fault=='external-pending':
        row=nw.read();row['phase']='creating';nw.save(row)
    elif fault=='missing-attachment':worker.intent['attachments']['blue']={}
    elif fault=='stopped':dw.values['1'*64]['State']['Running']=False
    elif fault=='replaced':
        row=dw.values.pop('1'*64);row['Id']='f'*64;dw.values['f'*64]=row
    elif fault=='dns-asset':(dns.asset_directory(dns.read())/'hosts').write_text('changed\n')
    before=(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes(),deepcopy(jw.values),deepcopy(dw.values),len(env.creates))
    with pytest.raises(JumphostError):worker.observe()
    assert before==(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes(),jw.values,dw.values,len(env.creates))


def test_observation_refuses_journal_change_during_resource_reads(runtime,monkeypatch):
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    original=worker.preflight
    def preflight():
        value=original();row=jump.read();row['observation_race']='changed';jump.save(row);return value
    monkeypatch.setattr(worker,'preflight',preflight)
    with pytest.raises(JumphostError,match='journals changed'):worker.observe()


def test_dns_packet_probe_uses_original_namespace_and_never_starts_services(runtime,monkeypatch):
    import json
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    worker.intent['dns_probe']={'server':worker.intent['dns']['config']['ip'],'records':[{'name':'r1','address':'198.18.0.11'}]}
    original=jump.run;seen=[]
    def run(argv,**kwargs):
        if argv[0]=='nsenter' and '-c' in argv and 'input' in kwargs:
            seen.append((argv,kwargs))
            request=json.loads(kwargs['input'])
            return json.dumps({'level':'dns-packets','server':request['server'],'answers':[
                dict(request['records'][0],type='A',transport=t) for t in ('udp','tcp')]})
        return original(argv,**kwargs)
    monkeypatch.setattr(jump,'run',run)
    before=(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes())
    value=worker.probe()
    assert value['phase']=='probed' and value['functional_readiness_verified'] is False
    assert value['dhcp']['level']=='disabled' and value['dns']['level']=='dns-packets'
    assert len(seen)==1 and seen[0][1]['pass_fds']
    assert seen[0][0][1]=='--net=/proc/self/fd/'+str(seen[0][1]['pass_fds'][0])
    assert before==(jump.path.read_bytes(),dns.path.read_bytes(),nw.path.read_bytes())


def test_dns_probe_refuses_records_outside_original_hosts_before_sending(runtime,monkeypatch):
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    worker.intent['dns_probe']={'server':worker.intent['dns']['config']['ip'],'records':[{'name':'foreign','address':'192.0.2.55'}]}
    with pytest.raises(JumphostError,match='not bound'):worker.probe()
    assert not any(v[0]=='nsenter' and '-c' in v and 'DNS packet probe' in v[-1] for v in jw.calls)


@pytest.mark.parametrize('case',['valid','missing-link-local','ambiguous-link-local','replaced-peer','changed-service'])
def test_packet_profile_requalifies_original_server_endpoint_and_service(runtime,monkeypatch,case):
    worker,jw,dw,env,jump,dns,nw=runtime;worker.apply()
    worker.intent['packet_probe_identities']={'default':{}}
    # Exercise the pure profile observation branch with IPv6 enabled; the
    # existing fixture materializes IPv4 only, while probe() is mocked here.
    worker.intent['attachments']['default']['attachment']['ipv6']='2001:db8::fe/64'
    seen=[]
    def probe():
        seen.append(True)
        return {'phase':'probed','original':'changed' if case=='changed-service' and len(seen)>1 else 'service'}
    monkeypatch.setattr(worker,'probe',probe)
    original=jump.run
    def run(argv,**kwargs):
        if argv[0]=='nsenter' and argv[2:]==['ip','-j','addr','show']:
            values=[{'family':'inet6','scope':'link','local':'fe80::fe','flags':[]}]
            if case=='missing-link-local':values=[]
            if case=='ambiguous-link-local':values.append(dict(values[0],local='fe80::ff'))
            return json.dumps([{'ifname':worker.intent['attachments']['default']['attachment']['interface'],'addr_info':values}])
        return original(argv,**kwargs)
    monkeypatch.setattr(jump,'run',run)
    if case=='replaced-peer':jw.peer[0]['address']='02:00:00:00:00:99'
    if case=='valid':
        result=worker.packet_profiles()
        assert result['phase']=='packet-profiles' and result['servers']['default']=={'mac':jump.read()['peer']['address'],'link_local':'fe80::fe'}
        assert len(seen)==2
    else:
        with pytest.raises(JumphostError):worker.packet_profiles()
