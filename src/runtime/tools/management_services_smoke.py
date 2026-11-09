#!/usr/bin/env python3
"""Single-host management/service gate with opt-in qualified workload admission.

Fixture teardown uses only original root journals. The sealed coordinator intent
is retained under the explicit output directory; guest/API qualification is opt-in.
"""
import argparse
from copy import deepcopy
from dataclasses import replace
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sys
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from management_service_diagnostics import DiagnosticHost,private_json,exception_chain,capture_before_cleanup,remove_fixture_external,probe_cleanup_order,compare_snapshot
from prepare_jumphost_candidate import audit_image
from management_barrier_smoke import Local
from smoke import Service,command
from cleanup_compatibility import require_qualified_cleanup
from dnlab_multinode.controllers.management_prepare import ManagementPreparation
from dnlab_multinode.models.topology import DistributedTopology,InfraHost,MgmtConfig,JumphostConfig,JumphostNet,VDNode
from dnlab_multinode.models.schedule import SchedulePlan,HostAssignment
from dnlab_multinode.models.state import DeploymentState,HostScheduleState
from dnlab_multinode.services import netsetup,management_barrier as barrier,state as states,jumphost,dns,management_service_runtime as services
from dnlab_multinode.services import management_probe_runtime as probe_runtime
from dnlab_multinode.services.management_probe_exec import execution_identity
from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.management_services import compile_services
from dnlab_multinode.services.management_dhcp import compile_dhcp
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.services.jumphost_network_host import Worker as ExternalWorker
from dnlab_multinode.services.realnet_vni import Registry
from dnlab_multinode.services.runtime_operations import OperationStore
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.hostsfile import HostEntry
from dnlab_runtime.backend import Docker,Linux

PLUGIN=Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
PLUGIN_STATE=Path('/var/lib/dnlab-vrf-plugin/state.json')


def fixture_coordinator(root, native_lifecycle):
    root=Path(root)
    if not native_lifecycle:return root/'coordinator'
    from dnlab_multinode.services.runtime_cleanup import operation_directory
    directory=operation_directory(root)
    if directory!=root/'.runtime-operations':
        raise RuntimeError('fixture refuses externally configured lifecycle ledger')
    return directory


def fixture_state(root,schedule,*,management_plan=None,publish_service_inventory=False,managed_initial_batch=False):
    """Keep original placement as metadata, without inventing VD bindings."""
    state=DeploymentState(lab_name=schedule.lab_name,topology_file=str(Path(root)/'fixture.yml'),
                          runtime_mode='custom',vrf_table_id=schedule.vrf_table_id)
    if publish_service_inventory:state.dnlab_deployed=False
    if management_plan is not None:state.management_plan=deepcopy(management_plan)
    if managed_initial_batch:
        state.scheduling={host:HostScheduleState(host=assignment.host_ip,topology_file='',vd=deepcopy(assignment.vd_names))
                          for host,assignment in schedule.assignments.items()}
    return state


def run(output,plugin_sha,jump_image,dns_image,*,dhcp_profile_diagnostic=False,probe_identities=False,probe_lifecycle=False,probe_packets=False,probe_recovery=False,probe_exec_crash=False,routing_snapshot=False,routing_packets=False,mixed_management=False,dns_clients=False,dns_path_diagnostic=False,ssh_access=False,gui_forward_image=None,release_network_services=False,http_workload_image=None,publish_service_inventory=False,managed_initial_batch=False,native_lifecycle_relay_image=None):
    if native_lifecycle_relay_image and not managed_initial_batch:raise ValueError("managed initial batch required for native lifecycle stage")
    if dns_path_diagnostic and probe_exec_crash:raise ValueError("diagnostic and crash fixtures are exclusive")
    if http_workload_image and not gui_forward_image:raise ValueError('GUI image required for qualified HTTP path')
    if managed_initial_batch and not http_workload_image:raise ValueError('HTTP image required for managed initial batch')
    require_qualified_cleanup(Docker())
    publish_service_inventory=publish_service_inventory or managed_initial_batch
    release_network_services=release_network_services or bool(http_workload_image) or publish_service_inventory
    ssh_access=ssh_access or bool(gui_forward_image)
    mixed_management=mixed_management or release_network_services
    dns_clients=dns_clients or dns_path_diagnostic or release_network_services
    routing_packets=routing_packets or mixed_management
    probe_packets=probe_packets or probe_recovery or probe_exec_crash or mixed_management
    probe_identities=probe_identities or probe_lifecycle or probe_packets or routing_packets or dns_clients
    if hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha:raise RuntimeError('plugin source differs')
    baseline=json.loads(PLUGIN_STATE.read_text())
    guard_paths=['controllers/management_prepare.py','controllers/management_routing_prepare.py','controllers/management_probe_requests.py','controllers/management_readiness.py','services/management_barrier.py']+['services/'+name+'.py' for name in ('runtime_cleanup','lab_cleanup','jumphost_host','dns_host','jumphost_network_host','management_service_host','management_service_runtime','management_segments','management_probe_identity','management_routing_observation','management_routing_probe','management_dns_probe','management_dns_client_probe','management_host','management_network_host','management_probe_host','management_probe_runtime','management_dhcpv4_probe','management_dhcpv6_probe','management_packet_probe','management_packet_receipt','management_probe_exec')]
    if publish_service_inventory:guard_paths+=['controllers/management_publication.py','services/dns.py']
    if managed_initial_batch:guard_paths+=['controllers/runtime_deploy.py','controllers/runtime_publication.py','services/runtime_manifest.py','services/runtime_operations.py']
    if native_lifecycle_relay_image:guard_paths+=['controllers/node.py','services/native_public.py','services/native_inventory.py','services/runtime_relay.py','services/relay_host.py','services/relay_resolution.py']
    def guard_sources():return {name:hashlib.sha256((SOURCE.parent/'multinode/dnlab_multinode'/name).read_bytes()).hexdigest() for name in guard_paths}
    original_guard_sources=guard_sources()
    root=Path(output)
    coordinator_dir=fixture_coordinator(root,bool(native_lifecycle_relay_image))
    root.mkdir(mode=0o700,parents=True,exist_ok=False)
    candidate_audit=audit_image(jump_image,root)
    token=uuid.uuid4().hex[:10];lab='drsp-'+token
    if probe_exec_crash:
        from management_probe_crash_host import ProbeCrashHost
        host=ProbeCrashHost(root)
    elif dns_path_diagnostic:
        from management_dns_path_host import DNSPathHost
        host=DNSPathHost(root)
    else:host=DiagnosticHost(root)
    api=Docker();linux=Linux()
    occupied=[ipaddress.ip_network(c['Subnet']) for n in api.request('GET','/networks') for c in (n.get('IPAM') or {}).get('Config') or [] if c.get('Subnet')]
    subnet=next(ipaddress.ip_network('198.19.'+str(i)+'.0/24') for i in range(100,200) if not any(s.version==4 and s.overlaps(ipaddress.ip_network('198.19.'+str(i)+'.0/24')) for s in occupied))
    tables={v.get('linkinfo',{}).get('info_data',{}).get('table') for v in json.loads(command(['ip','-j','-d','link','show']))}
    tables.update(v.get('table') for v in json.loads(command(['ip','-j','route','show','table','all'])))
    table=next(v for v in range(49000,51000) if v not in tables)
    network=JumphostNet(network='drsp-ext-'+token,bridge='dsx'+token,ipv4_subnet=str(subnet),ipv4_gw=str(subnet.network_address+1))
    topo=DistributedTopology(name=lab,master=InfraHost(name='master',host='127.0.0.1',ssh_user='root',ssh_key='unused',is_master=True),workers={},underlay_iface='lo',nodes={},links=[],
        jumphost=JumphostConfig(),jumphost_net=network,mgmt=MgmtConfig(network='unused',bridge='unused',ipv4_subnet='198.19.233.0/24',ipv4_gw='198.19.233.254'))
    topo.raw={'management_networks':{key:{'ipv4-subnet':'198.19.'+str(index)+'.0/24','ipv6-subnet':'2001:db8:'+str(index)+'::/64','dhcp':key=='default' if mixed_management else True} for key,index in [('default',233),('blue',234)]}}
    if http_workload_image:topo.nodes['http-vd']=VDNode(name='http-vd',kind='linux',image=http_workload_image)
    topo,model=resolve(topo,prepare_probes=probe_identities);abstract=compile_services(model,{'network':network.network,'bridge':network.bridge,'subnet':str(subnet),'gateway':network.ipv4_gw})
    extra_entries=(HostEntry('probe6-'+token+'.invalid',model['probes']['default']['ipv6'],'AAAA'),) if dns_clients else ()
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    external={'name':network.network,'bridge':network.bridge,'subnet':str(subnet),'gateway':network.ipv4_gw}
    resolver=str(subnet.network_address+2)
    configs={'dns':{'lab':lab,'generation':uuid.uuid4().hex,'name':abstract['dns']['container_name'],'image':dns_image,'network':external,'ip':resolver,'upstream':['192.0.2.53']},
        'jumphost':{'lab':lab,'generation':uuid.uuid4().hex,'name':abstract['jumphost']['container_name'],'image':jump_image,'network':external,
            'ip':str(subnet.network_address+3),'env':{'JUMPHOST_PASSWORD':uuid.uuid4().hex,'JUMPHOST_LAB_NAME':lab},'bind_ip':'127.0.0.1','port':port,'dns':[resolver],'binds':[],
            'dhcp':compile_dhcp(topo,model,abstract,resolver),'attachment':abstract['jumphost']['attachments']['default']['config'],'management_intent':_expected_network(topo,'master')}}
    ssh_key=None
    if ssh_access:
        from management_ssh_probe import prepare_key
        ssh_key=prepare_key(root)
        configs['jumphost']['env']['JUMPHOST_AUTHORIZED_KEYS']=ssh_key['public']
    host.secrets=[configs['jumphost']['env']['JUMPHOST_PASSWORD']]
    private_json(root/'plugin-baseline.json',baseline)
    assignments={'master':HostAssignment('master','127.0.0.1',['http-vd'])} if http_workload_image else {}
    schedule=SchedulePlan(lab_name=lab,assignments=assignments,vrf_table_id=table)
    state=fixture_state(root,schedule,management_plan=model if probe_identities else None,
                        publish_service_inventory=publish_service_inventory,managed_initial_batch=managed_initial_batch)
    registry=Registry(root/'vni');store=None;(root/'runtime').mkdir(mode=0o700);service=Service('native',root/'runtime',None,lab)
    paths=replace(netsetup.PATHS,management_journal_dir=str(root/'management'),management_probe_journal_dir=str(root/'probes'),jumphost_journal_dir=str(root/'jump'),dns_journal_dir=str(root/'dns'),jumphost_network_journal_dir=str(root/'external'),relay_journal_dir=str(root/'relay'))
    from dnlab_multinode.services import runtime_relay as relays
    originals={m:m.PATHS for m in (netsetup,jumphost,dns,services,probe_runtime,relays)}
    for m in originals:m.PATHS=paths
    report={'status':'running','candidate_audit':candidate_audit,'checks':[],'scope':'one physical host; two management L2 networks; no guest or functional service readiness claim','functional_readiness_verified':False,'physical_multihost_verified':False}
    if mixed_management:
        assert model['networks']['blue']['dhcp'] is False and abstract['dhcp_segments']==['default']
        text=configs['jumphost']['dhcp'];peer=abstract['jumphost']['attachments']['blue']['config']['interface']
        assert 'interface='+peer+'\n' in text and 'no-dhcp-interface='+peer+'\n' in text
        assert model['probes']['blue']['mac'] not in text and model['probes']['blue']['duid'] not in text
        report['management_dhcp_enabled']={key:value['dhcp'] for key,value in model['networks'].items()}
        report['checks'].append('mixed management intent keeps blue DHCP disabled and excludes its interface and infrastructure reservation from rendered DHCP/RA service configuration')
    http_workload=None;native_stage=None
    def save():states.save_state(state,root)
    try:
        service.start();runtime=RuntimeClient(Local(),socket_path=service.client.socket_path)
        if native_lifecycle_relay_image:
            from relay_console_smoke import process_proof
            private_json(root/'native-runtime-process.json',process_proof(service.process.pid))
        runtime=runtime.bound_to(runtime.qualify_node(inspection=True)['journal_id'])
        targets={'master':{'target':{'host':'master','socket_path':service.client.socket_path,'container_name':None},'journal_id':runtime.expected_journal_id}}
        store=OperationStore(coordinator_dir);controller=ManagementPreparation(store,lambda target:runtime)
        host.phase='infrastructure'
        controller.apply('services',topo,schedule,{'master':'127.0.0.1'},targets,state,{'master':host},save,registry=registry,service_configs=configs,extra_dns_entries=extra_entries)
        if probe_identities:
            original=controller.driver.original(lab,'services')
            assert original['plan']['services']['packet_probe_identities']==model['probes']
            report['probe_identity_reservations']=model['probes']
            for segment,row in model['probes'].items():
                expected=original['plan']['hosts']['master']['segments'][segment]['network']
                assert row['ipv4'] in expected['reserved'] and row['ipv6'] in expected['reserved']
            report['checks'].append('original coordinator intent binds infrastructure probe identities; existing anchor IPv4 and dedicated IPv6 protected by qualified Docker/IPAM proof; no probe endpoint allocated')
        host.phase='service-materialization'
        first=controller.provision_services('services',lab,state,{'master':host},save)
        receipt=deepcopy(first['services']['receipt'])
        assert receipt['functional_readiness_verified'] is False and first['phase']=='provisioning'
        store.close();store=OperationStore(coordinator_dir);controller=ManagementPreparation(store,lambda target:runtime)
        host.phase='service-replay'
        repeated=controller.provision_services('services',lab,state,{'master':host},save)
        assert repeated['services']['receipt']==receipt
        assert state.jumphost is None and state.dns is None
        report['checks'].append('standalone coordinator provisions original external/DNS/jumphost and two attachments; replay after reopening ledger preserves IDs and nonces')
        host.phase='service-observation'
        observed=controller.observe_services('services',lab,state,{'master':host},save)
        observation=observed['services']['observation']
        assert observed['phase']=='provisioning' and observation['services']['functional_readiness_verified'] is False
        assert observation['services']['mutations_performed'] is False
        assert set(observation['services']['management_networks'])=={'default','blue'}
        assert controller.observe_services('services',lab,state,{'master':host},save)['services']['observation']==observation
        report['observation']=observation
        report['checks'].append('read-only service observation requalifies both management attachments and original helper births; repeat is stable and functional readiness remains unqualified')
        host.phase='service-probes'
        probed=controller.probe_services('services',lab,state,{'master':host},save)
        probes=probed['services']['probes']
        assert probes['dns']['level']=='dns-packets' and probes['dhcp']['level']=='dhcp-listeners'
        assert probes['functional_readiness_verified'] is False and probed['phase']=='provisioning'
        report['probes']=probes
        report['checks'].append('DNS UDP/TCP packets from qualified jumphost namespace and DHCP process/listener proof pass; DHCP packet readiness and fence release remain unqualified')
        if ssh_access:
            from management_ssh_probe import probe as ssh_probe
            host.phase='ssh-authentication'
            report['ssh_authentication']=ssh_probe(root,lab,configs['jumphost'],ssh_key)
            report['checks'].append('original published jumphost authenticates dedicated key as labuser with pinned server key; bounded readonly id command exits0 and client closes; no VD/WebUI reachability claim')
        if gui_forward_image and not http_workload_image:
            from management_gui_forward import probe as gui_probe
            host.phase='gui-openssh-forwarding'
            bundle=controller.driver.original(lab,'services')['plan']['services']
            report['gui_forwarding']=gui_probe(root,lab,bundle,ssh_key,gui_forward_image)
            report['checks'].append('container-owned actual GUI OpenSSH forwards to central DNS and both segment proxies; original DNS answers, target replacement and reuse pass; no VD/HTTP claim')
        if routing_snapshot:
            host.phase='routing-control-plane-observation'
            intent=controller.driver.original(lab,'services')['plan']['services']
            before_state=deepcopy(state.to_dict())
            snapshot=services.invoke(host,intent,'routing_snapshot')
            report['routing_snapshot']=snapshot
            private_json(root/'routing-snapshot.json',snapshot,host.secrets)
            assert snapshot['validation']['status']=='accepted', 'routing prerequisites rejected; see routing-snapshot.json'
            assert snapshot['functional_readiness_verified'] is False and snapshot['service_mutations_performed'] is False
            assert state.to_dict()==before_state
            report['checks'].append('read-only original jumphost forwarding, connected/default routes and policy prerequisites observed; firewall dumps retained without certification; no packet routing or readiness claim')
        if probe_lifecycle:
            host.phase='probe-endpoint-lifecycle'
            lifecycle=controller.qualify_probe_lifecycle('services',lab,state,{'master':host},save)
            assert lifecycle['probe_lifecycle']['phase']=='completed' and lifecycle['phase']=='provisioning'
            before=deepcopy(lifecycle['probe_lifecycle'])
            assert controller.qualify_probe_lifecycle('services',lab,state,{'master':host},save)['probe_lifecycle']==before
            report['probe_lifecycle']=before
            report['checks'].append('journaled probe birth, qualified namespace/endpoint and ordinary cleanup complete sequentially for both management networks; replay only verifies cleanup; no DHCP packet or readiness release claim')
        if probe_packets:
            host.phase='probe-dhcp-packets'
            if probe_exec_crash:
                from management_probe_recovery import caused_by_worker_crash
                host.crash_pending=True
                try:controller.qualify_probe_packets('services',lab,state,{'master':host},save)
                except Exception as error:
                    if not caused_by_worker_crash(error) or not host.crash_verified:raise
                else:raise RuntimeError('fixture worker SIGKILL was not reached')
                row=barrier.get(store,lab);progress=row['packet_probes'];assert len(progress['entries'])==1
                rid=next(iter(progress['entries']));entry=progress['entries'][rid]
                request=next(v for v in progress['requests'] if v['request_id']==rid)
                key=barrier.digest(['management-probe-v1',request]);path=root/'probes'/(key+'.json')
                local=json.loads(path.read_text());op=local['packet_execution']
                assert entry['phase']=='applying' and local['phase']=='active' and op['start_attempted'] and not op['exit_verified']
                assert op['id']==entry['execution']['id'] and op['nonce']==entry['execution']['nonce']
                deadline=time.monotonic()+5
                while True:
                    data=Path(op['files']['output']['path']).read_text()
                    if data.endswith('\n') and data:break
                    if time.monotonic()>=deadline:raise RuntimeError('fixture packet client birth not observed')
                    time.sleep(.02)
                evidence=[json.loads(line) for line in data.splitlines()]
                assert len(evidence)==1 and evidence[0]['kind']=='birth' and evidence[0]['nonce']==op['nonce']
                current=api.request('GET','/exec/'+op['id']+'/json')
                assert current['Running'] and current['ContainerID']==entry['birth']['container_id']
                report['probe_exec_crash']={'worker_sigkill_verified':True,'exec_running_after_worker_exit':True,
                    'execution':entry['execution'],'birth':entry['birth'],'client_birth':evidence[0]['value'],
                    'create_calls':op['create_calls'],'start_calls':op['start_calls'],'permit_before_crash':False}
                private_json(root/'probe-exec-crash.json',report['probe_exec_crash'])
                store.close();state=states.load_state(lab,root);assert state is not None
                store=OperationStore(coordinator_dir);controller=ManagementPreparation(store,lambda target:runtime)

            if probe_recovery:
                from management_probe_recovery import ProbeBoundary,LostProbeAcknowledgment
                original_invoke=probe_runtime.invoke;boundary=ProbeBoundary(original_invoke);cuts=[]
                probe_runtime.invoke=boundary
                try:
                    while True:
                        try:
                            tested=controller.qualify_probe_packets('services',lab,state,{'master':host},save)
                            break
                        except LostProbeAcknowledgment:
                            row=barrier.get(store,lab);progress=row['packet_probes'];loss=boundary.losses[-1]
                            entry=progress['entries'][loss['request_id']]
                            assert len(progress['entries'])==1 and entry['birth']==loss['expected_birth']
                            request=next(v for v in progress['requests'] if v['request_id']==loss['request_id'])
                            key=barrier.digest(['management-probe-v1',request])
                            local=json.loads((root/'probes'/(key+'.json')).read_text())
                            assert local['coordinator_birth']==entry['birth']
                            if loss['action']=='packets':
                                assert entry['phase']=='applying' and local['phase']=='active' and local['packet_phase']=='completed'
                            else:
                                assert entry['phase']=='cleanup_pending' and local['phase']=='cleaned' and local['cleanup_verified']
                            cuts.append({'action':loss['action'],'request_id':loss['request_id'],'birth':entry['birth'],
                                'coordinator_phase':entry['phase'],'local_phase':local['phase'],'packet_phase':local['packet_phase']})
                            private_json(root/'probe-recovery-cuts.json',cuts)
                            store.close();state=states.load_state(lab,root)
                            assert state is not None
                            store=OperationStore(coordinator_dir);controller=ManagementPreparation(store,lambda target:runtime)
                    assert not boundary.pending and len(cuts)==2
                    recovered_id=cuts[0]['request_id'];assert cuts[1]['request_id']==recovered_id
                    sequence=[v['action'] for v in boundary.calls if v['request_id']==recovered_id]
                    assert sequence.count('ensure')==(0 if probe_exec_crash else 1) and sequence.count('inspect')==(2 if probe_exec_crash else 1) and sequence.count('packets')==2
                    report['probe_recovery']={'cuts':cuts,'calls':boundary.calls,'coordinator_reopened_after_each_loss':True}
                    report['checks'].append('lost packet and cleanup acknowledgments after durable local results recover the same birth after coordinator ledger/state reload; bound recovery uses read-only inspect and no second ensure; next segment waits for verified cleanup')
                finally:probe_runtime.invoke=original_invoke
            else:
                tested=controller.qualify_probe_packets('services',lab,state,{'master':host},save)
            before=deepcopy(tested['packet_probes'])
            assert before['phase']=='completed' and tested['phase']=='provisioning'
            assert {request['segment'] for request in before['requests']}==set(abstract['dhcp_segments'])
            assert all(row['packets']['ipv4']['ack']['type']==5 and row['packets']['ipv6']['reply']['type']==7
                for row in before['entries'].values())
            assert controller.qualify_probe_packets('services',lab,state,{'master':host},save)['packet_probes']==before
            if probe_exec_crash:
                local=json.loads(path.read_text());op=local['packet_execution']
                assert op['id']==report['probe_exec_crash']['execution']['id'] and op['exit_verified'] and op['exit_code']==0
                assert op['create_calls']==1 and op['start_calls']==1 and local['phase']=='cleaned'
                report['probe_exec_crash'].update(same_exec_recovered=True,exit_verified=True,cleanup_verified=True)
                report['checks'].append('actual fixture worker SIGKILL after detached packet exec start leaves the owned client awaiting permit; ledger/state reload recovers the same exec, one create/start, durable progress and verified exit before cleanup')
            report['packet_probes']=before
            report['checks'].append('original infrastructure probes receive DHCPv4 ACK and DHCPv6 REPLY/RA only on DHCP-enabled management networks; original service process requalified before/after; replay verifies cleanup without retransmission; fence remains active')
        if routing_packets:
            host.phase='routing-packets'
            qualified=controller.qualify_routing('services',lab,state,{'master':host},save)
            result=deepcopy(qualified['routing_probes'])
            report['routing_probes']=result
            private_json(root/'routing-packets.json',result,host.secrets)
            assert result['phase']=='completed' and result['packet_forwarding_verified'] is True
            assert len(result['pairs'])==1 and len(result['entries'])==2
            assert all(set(entry['packets']['families'])=={'4','6'} and entry['phase']=='cleaned' for entry in result['entries'].values())
            assert controller.qualify_routing('services',lab,state,{'master':host},save)['routing_probes']==result
            report['checks'].append('owned paired probes exchange IPv4/IPv6 UDP through original jumphost with preserved IPs, hop63 and reciprocal acknowledgments; both execs exit before either endpoint is removed; replay only verifies cleanup; no access/global readiness claim')
        if dns_clients:
            host.phase='dns-client-packets'
            qualified=controller.qualify_dns_clients('services',lab,state,{'master':host},save)
            dns_result=deepcopy(qualified['dns_client_probes'])
            report['dns_client_probes']=dns_result
            private_json(root/'dns-clients.json',dns_result,host.secrets)
            assert dns_result['phase']=='completed' and qualified['phase']=='provisioning'
            assert {request['segment'] for request in dns_result['requests']}==set(model['networks'])
            for request in dns_result['requests']:
                entry=dns_result['entries'][request['request_id']];answers=entry['packets']['answers']
                assert entry['phase']=='cleaned' and {row['type'] for row in answers.values()}=={'A','AAAA'}
                assert {row['transport'] for row in answers.values()}=={'udp','tcp'}
                assert all(row['tcp_closed'] for row in answers.values() if row['transport']=='tcp')
                assert set(request['packet_profile']['resolvers'])==({'4','6'} if model['networks'][request['segment']]['ipv6_subnet'] else {'4'})
            assert controller.qualify_dns_clients('services',lab,state,{'master':host},save)['dns_client_probes']==dns_result
            report['checks'].append('original probe clients on every management resolve bound A/AAAA records over UDP/TCP; IPv4/IPv6 use each segment proxy with qualified central upstream, including static segments; TCP FIN/ACK closure and original exec exits precede cleanup; replay sends no new queries; fence retained')
        body={'schema_version':1,'lab_id':lab,'node_id':'vd','request_id':'denied-start','action':'start','expected_revision':0,'spec':{'kind':'linux','image':'sha256:'+'a'*64,'container_name':'drsp-'+token+'-vd'}}
        try:runtime.submit_node(body)
        except RuntimeError:pass
        else:raise RuntimeError('workload crossed materialization-only barrier')
        report['checks'].append('workloads remain fenced after service materialization; no readiness/release inferred')
        if release_network_services:
            host.phase='network-service-readiness-release'
            result=controller.release_network_services('services',lab,state,{'master':host})
            assert result['phase']=='released' and result['release_checks']=={'master':1}
            assert result['readiness']['hosts']['master']['scope']=='management-network-services-v1'
            assert controller.release_network_services('services',lab,state,{'master':host})==result
            report['network_service_release']={'phase':result['phase'],'readiness_fingerprint':result['readiness_fingerprint'],
                'release_checks':result['release_checks'],'guest_readiness_verified':False}
            report['checks'].append('original all-host DHCP/DNS/routing qualifications and probe cleanup reobserved before network-service fence release; no guest/application readiness claim')
        if publish_service_inventory:
            from dnlab_multinode.controllers.management_publication import publish
            host.phase='management-service-publication'
            load=lambda:states.load_state(lab,root)
            checkpoint=lambda value:states.save_state(value,root)
            state=publish(controller,'services',lab,state,{'master':host},load,checkpoint)
            original=controller.driver.original(lab,'services')
            assert state.jumphost.generation==configs['jumphost']['generation']
            assert state.jumphost.ssh_bind_ip==configs['jumphost']['bind_ip']
            assert state.jumphost.ssh_port==configs['jumphost']['port']
            assert state.dns.generation==configs['dns']['generation']
            assert original['services']['receipt']==receipt
            assert state.dnlab_deployed is False and state.node_runtime=={}
            snapshot=state.to_dict()
            store.close();store=OperationStore(coordinator_dir)
            controller=ManagementPreparation(store,lambda target:runtime)
            state=publish(controller,'services',lab,load(),{'master':host},load,checkpoint)
            assert state.to_dict()==snapshot and controller.driver.original(lab,'services')==original
            report['public_service_inventory']={
                'jumphost':{'container':state.jumphost.container,'generation':state.jumphost.generation,
                    'ssh_port':state.jumphost.ssh_port,'ssh_bind_ip':state.jumphost.ssh_bind_ip},
                'dns':{'container':state.dns.container,'generation':state.dns.generation,'hosts_file':state.dns.hosts_file},
                'same_after_reopen':True,'dnlab_deployed':state.dnlab_deployed}
            report['checks'].append('original DNS/jumphost inventory published only after service release; exact access metadata and qualified asset path persist after coordinator reopen, without new helper generations or declaring deployment complete')
        if http_workload_image:
            from http_workload_fixture import Workload
            from management_gui_forward import probe as gui_probe
            host.phase='native-http-workload'
            management={'network':model['networks']['default']['network'],
                        'ipv4':model['ledgers']['ipv4']['default']['http-vd'],
                        'ipv6':model['ledgers']['ipv6']['default']['http-vd'],
                        'mac':model['ledgers']['mac']['http-vd']}
            if managed_initial_batch:
                from managed_http_workload_fixture import ManagedWorkload
                http_workload=ManagedWorkload(root,topo,schedule,'http-vd',http_workload_image,management,
                    targets['master']['target'],runtime,store,'services',management_clients={'master':host})
            else:http_workload=Workload(root,lab,'http-vd',http_workload_image,management,targets['master']['target'],runtime,store)
            http_target=http_workload.ensure()
            report['http_workload_admission']={'container_id':http_workload.record['container_id'],
                'revision':http_workload.record['revision'],'target':http_target,'coordinator_managed':True}
            if managed_initial_batch:
                from dnlab_multinode.controllers.runtime_publication import publish as publish_workloads
                host.phase='native-initial-workload-publication'
                private_json(root/'initial-publication-before.json',{'state':state.to_dict(),'batch_id':http_workload.key},host.secrets)
                state=publish_workloads(http_workload.batch,lab,http_workload.key,state,load,checkpoint)
                published=state.to_dict()
                host.phase='native-initial-workload-publication:inventory'
                private_json(root/'initial-publication-persisted.json',published,host.secrets)
                compare_snapshot(root,'initial-publication-inventory',True,
                                 set(state.node_runtime)=={'http-vd'} and not state.dnlab_deployed,host.secrets)
                host.phase='native-initial-workload-publication:binding'
                compare_snapshot(root,'initial-publication-binding',http_workload.batch.bindings(lab,http_workload.key)['http-vd'],
                                 state.node_runtime['http-vd'].runtime_binding,host.secrets)
                host.phase='native-initial-workload-publication:replay'
                replayed=publish_workloads(http_workload.batch,lab,http_workload.key,load(),load,checkpoint).to_dict()
                compare_snapshot(root,'initial-publication-replay',published,replayed,host.secrets)
                report['initial_workload_publication']={'batch_id':http_workload.key,'container_id':http_workload.record['container_id'],
                    'original_management_parent':http_workload.record['admission']['parent'],'replay_unchanged':True,'dnlab_deployed':False}
                report['checks'].append('compiled initial batch consumes original released management parent and publishes original VD binding durably; replay preserves generation and deployment remains incomplete')
            bundle=controller.driver.original(lab,'services')['plan']['services']
            host.phase='gui-native-http-proxy'
            report['gui_forwarding']=gui_probe(root,lab,bundle,ssh_key,gui_forward_image,http_target=http_target)
            assert report['gui_forwarding']['client']['webui_http_verified'] is True
            http_workload.verify()
            report['checks'].append('native workload admitted through original coordinator after network-service release; actual GUI opening and HTTP proxy routes return nonce-bound guest payload through original SSH tunnel')
        if native_lifecycle_relay_image:
            from native_jumphost_stage import NativeJumphostStage
            host.phase='native-jumphost-lifecycle'
            native_stage=NativeJumphostStage(root,topo,state,store,runtime,host,
                                            native_lifecycle_relay_image,network.ipv4_gw)
            state=native_stage.prepare()
            relay_before=native_stage.relay_snapshot('before')
            cli_before=native_stage.probe_cli('before',http_workload.record['nonce'])
            state=native_stage.restart()
            cli_after=native_stage.probe_cli('after',http_workload.record['nonce'])
            relay_after=native_stage.relay_snapshot('after')
            compare_snapshot(root,'native-relay-process-stability',relay_before,relay_after,host.secrets)
            report['native_jumphost_lifecycle']={
                'births':deepcopy(native_stage.lifecycle.record['births']),
                'steps':deepcopy(native_stage.lifecycle.record['steps']),
                'relay_container_id':native_stage.proof['container_id'],
                'relay_process_before':relay_before,'relay_process_after':relay_after,
                'cli_before':cli_before,'cli_after':cli_after,'cli_verified':True,
                'scope':'public lifecycle, inventory publication and qualified original jumphost CLI'}
        report['receipt']=receipt;report['status']='passed'
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
        private_json(root/'original-error.json',{'phase':host.phase,'causes':exception_chain(error)},host.secrets)
        if dhcp_profile_diagnostic and host.phase=='service-probes':
            from dhcp_profile_diagnostics import diagnose
            from dnlab_multinode.services.jumphost_host import Worker
            try:
                report['dhcp_profile_diagnostic']=diagnose(Worker(lab,directory=paths.jumphost_journal_dir,
                    management_directory=paths.management_journal_dir),configs['jumphost'],root/'dhcp-profile-diagnostic.json')
                report['status']='diagnosed'
            except Exception as diagnostic:
                report['diagnostic_failure']=exception_chain(diagnostic)
    finally:
        errors=[];ids=[];names=[]
        if native_stage is not None:
            try:
                report['native_jumphost_cleanup']=native_stage.cleanup()
                ids.extend(row['container_id'] for row in native_stage.lifecycle.record['births'])
                ids.append(native_stage.proof['container_id'])
            except Exception as error:errors.append('native lifecycle: '+str(error))
        if http_workload is not None and native_stage is None:
            try:
                http_workload.cleanup()
                if http_workload.record.get('container_id'):ids.append(http_workload.record['container_id'])
                report['http_workload_cleanup']=deepcopy(http_workload.record)
            except Exception as error:errors.append('HTTP workload: '+str(error))
        try:capture_before_cleanup(root,host,api,store,lab)
        except Exception as error:private_json(root/'snapshot-error.json',exception_chain(error),host.secrets)
        host.phase='cleanup'
        if gui_forward_image:
            from management_gui_forward import pending as gui_pending
            if gui_pending(root):errors.append('GUI client cleanup pending; dependencies preserved')
        for path in probe_cleanup_order(root/'probes'):
            try:
                record=json.loads(path.read_text())
                original=barrier.get(store,lab) if store else None
                owned=sum([(original or {}).get(field,{}).get('requests',[]) for field in ('probe_lifecycle','packet_probes','dns_client_probes')],[])
                owned+=sum([pair['requests'] for pair in (original or {}).get('routing_probes',{}).get('pairs',[])],[])
                if record['request'] not in owned:
                    raise RuntimeError('probe cleanup original coordinator request missing')
                probe_runtime.invoke(host,record['request'],'cleanup',expected_birth=record.get('coordinator_birth'),expected_execution=execution_identity(record))
                probe_runtime.invoke(host,record['request'],'verify-cleaned',expected_birth=record.get('coordinator_birth'),expected_execution=execution_identity(record))
                if record.get('container_id'):ids.append(record['container_id'])
                if record.get('host'):names.append(record['host']['ifname'])
            except Exception as error:errors.append('probe: '+str(error))
        # Complete child journal cleanup before removing their infrastructure.
        for role,module in (() if errors else (('jumphost',jumphost),('dns',dns))):
            try:
                record=module._guard(host,lab,'read')
                if record['phase']=='absent':
                    if api.request('GET','/containers/'+configs[role]['name']+'/json',missing_ok=True):raise RuntimeError('unbound fixture helper birth')
                    continue
                if record['config']!=configs[role]:raise RuntimeError('fixture helper configuration differs')
                if record.get('container_id'):ids.append(record['container_id'])
                module._guard(host,lab,'delete',{'generation':configs[role]['generation']})
                request={'container':configs[role]['name'],'generation':configs[role]['generation']} if role=='jumphost' else {'generation':configs[role]['generation']}
                module._guard(host,lab,'verify-cleaned',request)
            except Exception as error:errors.append(role+': '+str(error))
        if not errors and state.mgmt:
            try:
                record=netsetup.invoke(host,'read',state.mgmt.infrastructure['plans']['master'])['record']
                if record:
                    ids.extend(v['id'] for v in record.get('networks',{}).values() if v.get('id'));names.extend(record.get('resources',{}))
                netsetup.destroy_management(state,{'master':host},checkpoint=save,registry=registry)
            except Exception as error:errors.append('management: '+str(error))
        if not errors:
            try:
                config={('network' if k=='name' else k):v for k,v in external.items()}
                worker=ExternalWorker(config,directory=root/'external')
                identifier=remove_fixture_external(worker,api)
                if identifier:ids.append(identifier);names.append(network.bridge)
            except Exception as error:errors.append('external: '+str(error))
        try:service.stop()
        except Exception as error:errors.append('runtime: '+str(error))
        if store is not None:
            original=barrier.get(store,lab)
            report['coordinator_barrier_retained_for_diagnostic']=bool(original and original['phase']=='provisioning');store.close()
        for m,value in originals.items():m.PATHS=value
        for identifier in ids:
            if api.request('GET','/containers/'+identifier+'/json',missing_ok=True) is not None or api.request('GET','/networks/'+identifier,missing_ok=True) is not None:errors.append('fixture ID remains')
        if any(linux.link(name) is not None for name in names):errors.append('fixture kernel link remains')
        if json.loads(PLUGIN_STATE.read_text())!=baseline or hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha:errors.append('installed plugin changed')
        report['runtime_guard_sources_unchanged']=guard_sources()==original_guard_sources
        report['guard_sources']=original_guard_sources
        if not report['runtime_guard_sources_unchanged']:errors.append('runtime guard source changed')
        report['cleanup']={'verified':not errors,'errors':errors,'runtime_stopped':service.process is None,'plugin_source_and_state_unchanged':'installed plugin changed' not in errors}
        if errors:report['status']='failed'
        private_json(root/'report.json',report,host.secrets);print(json.dumps(report),flush=True)
    if report['status'] not in ('passed','diagnosed'):raise RuntimeError('management service gate failed; see original report')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--jumphost-image',required=True);parser.add_argument('--dns-image',required=True);parser.add_argument('--dhcp-profile-diagnostic',action='store_true');parser.add_argument('--probe-identities',action='store_true');parser.add_argument('--probe-lifecycle',action='store_true');parser.add_argument('--probe-packets',action='store_true');parser.add_argument('--probe-recovery',action='store_true');parser.add_argument('--probe-exec-crash',action='store_true');parser.add_argument('--routing-snapshot',action='store_true');parser.add_argument('--routing-packets',action='store_true');parser.add_argument('--mixed-management',action='store_true');parser.add_argument('--dns-clients',action='store_true');parser.add_argument('--dns-path-diagnostic',action='store_true');parser.add_argument('--ssh-access',action='store_true');parser.add_argument('--gui-forward-image');parser.add_argument('--release-network-services',action='store_true');parser.add_argument('--http-workload-image');parser.add_argument('--publish-service-inventory',action='store_true');parser.add_argument('--managed-initial-batch',action='store_true');parser.add_argument('--native-lifecycle-relay-image');args=parser.parse_args()
    run(args.output,args.plugin_sha256,args.jumphost_image,args.dns_image,dhcp_profile_diagnostic=args.dhcp_profile_diagnostic,probe_identities=args.probe_identities,probe_lifecycle=args.probe_lifecycle,probe_packets=args.probe_packets,probe_recovery=args.probe_recovery,probe_exec_crash=args.probe_exec_crash,routing_snapshot=args.routing_snapshot,routing_packets=args.routing_packets,mixed_management=args.mixed_management,dns_clients=args.dns_clients,dns_path_diagnostic=args.dns_path_diagnostic,ssh_access=args.ssh_access,gui_forward_image=args.gui_forward_image,release_network_services=args.release_network_services,http_workload_image=args.http_workload_image,publish_service_inventory=args.publish_service_inventory,managed_initial_batch=args.managed_initial_batch,native_lifecycle_relay_image=args.native_lifecycle_relay_image)
