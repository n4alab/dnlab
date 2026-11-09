"""Opt-in offline management infrastructure preparation under the runtime fence.

Placement and participating hosts remain the caller's decision. This operation
stops at infrastructure-ready: services must be materialized and qualified by
the same original intent before the coordinator can release the workload fence.
"""
from copy import deepcopy
from dataclasses import asdict
import uuid

from ..models.state import MgmtState
from ..services import management_barrier as barrier,netsetup
from ..services.management_segments import normalize
from ..services.mgmt_network import _expected_network
from ..services.runtime_operations import RuntimeOperationError,digest
from ..utils import naming


def compile_inputs(topo,schedule,ips,*,management_generation,service_configs=None,service_model=None,extra_dns_entries=()):
    topo=normalize(topo)
    if service_configs is not None:
        from ..services.management_segments import resolve
        # Network/IPAM and helper proofs must use the same original ledger,
        # including opt-in infrastructure probe reservations.
        topo,service_model=resolve(topo,service_model)
    if (set(ips)!=set(topo.all_hosts) or schedule.lab_name!=topo.name
            or type(schedule.vrf_table_id) is not int or schedule.vrf_table_id<1):
        raise RuntimeOperationError('complete management host inventory and VRF required')
    hosts={}
    for host,ip in sorted(ips.items()):
        segments={}
        for key,cfg in sorted(topo.management_networks.items()):
            selected=deepcopy(topo);selected.mgmt=cfg
            segments[key]={'bridge':cfg.bridge,'vxlan':naming.mgmt_vxlan_iface(topo.name) if key=='default' else 'vm'+digest([topo.name,key])[:13],
                'underlay':topo.underlay_iface,'local':ip,'remotes':sorted(value for h,value in ips.items() if h!=host),
                'address':(cfg.docker_ipv4_gw or cfg.ipv4_gw)+'/'+cfg.ipv4_subnet.split('/')[1],
                'network':_expected_network(selected,host)}
        hosts[host]={'vrf':naming.vrf_name(topo.name),'table':schedule.vrf_table_id,'segments':segments}
    desired={'schema_version':1,'kind':'management-infrastructure','lab':topo.name,
        'management_generation':management_generation,'hosts':hosts}
    if service_configs is not None:
        from ..services.management_service_intent import compile_service_intent
        desired['services']=compile_service_intent(topo,service_model,service_configs,extra_dns_entries=extra_dns_entries)
    elif service_model is not None or extra_dns_entries:
        raise RuntimeOperationError('service inputs require explicit service configurations')
    return topo,desired


def validate_growth(state,desired):
    previous=state.mgmt.infrastructure if state.mgmt else None
    if previous is None:return
    if (not previous or previous.get('phase')!='active' or previous.get('network_phase')!='active'
            or set(previous.get('plans',{}))!=set(desired['hosts'])):
        raise RuntimeOperationError('complete active management baseline required; host extension is a separate operation')
    if previous.get('generation')!=desired['management_generation']:
        raise RuntimeOperationError('management generation changed')
    for host,old in previous['plans'].items():
        current=desired['hosts'][host]
        if old['vrf']!=current['vrf'] or old['table']!=current['table']:
            raise RuntimeOperationError('existing management VRF cannot change')
        for key,segment in old['segments'].items():
            projected=current['segments'].get(key)
            if (projected is None or {k:v for k,v in segment.items() if k!='vni'}!={k:v for k,v in projected.items() if k!='network'}
                    or previous.get('networks',{}).get(host,{}).get(key)!=projected['network']):
                raise RuntimeOperationError('existing management change/removal requires a separate operation')


class ManagementPreparation:
    def __init__(self,store,client_factory):
        self.store=store;self.driver=barrier.Driver(store,client_factory)

    def prepare(self,key,topo,schedule,ips,targets,state,*,lab_generation=1,service_configs=None,extra_dns_entries=()):
        if state.lab_name!=topo.name or state.runtime_mode!='custom' or state.teardown_requested:
            raise RuntimeOperationError('qualified custom lab required for offline management preparation')
        previous=barrier.get(self.store,topo.name)
        retry=previous and previous['request_id']==key
        generation=(previous['plan']['management_generation'] if retry
                    else (state.mgmt.infrastructure.get('generation') if state.mgmt else None) or uuid.uuid4().hex)
        _,desired=compile_inputs(topo,schedule,ips,management_generation=generation,service_configs=service_configs,
            service_model=(state.management_plan or None) if service_configs is not None else None,extra_dns_entries=extra_dns_entries)
        if set(targets)!=set(ips):raise RuntimeOperationError('all original management runtime targets required')
        if not retry:validate_growth(state,desired)
        return self.driver.prepare(topo.name,key,desired,targets,generation=lab_generation)

    def apply(self,key,topo,schedule,ips,targets,state,clients,checkpoint,*,registry=None,lab_generation=1,service_configs=None,extra_dns_entries=()):
        if set(clients)!=set(ips):raise RuntimeOperationError('all management clients required')
        intent=self.prepare(key,topo,schedule,ips,targets,state,lab_generation=lab_generation,
            service_configs=service_configs,extra_dns_entries=extra_dns_entries)
        if intent['phase'] in ('released','cancelled'):return intent
        if intent['phase'] in ('acquiring','held'):self.driver.acquire(topo.name,key)
        self.driver.begin_provisioning(topo.name,key)
        with self.driver.provisioning(topo.name,key):
            current=self.driver.original(topo.name,key)
            original=current['plan'];resolved,compiled=compile_inputs(topo,schedule,ips,management_generation=original['management_generation'],
                service_configs=service_configs,service_model=(state.management_plan or None) if service_configs is not None else None,
                extra_dns_entries=extra_dns_entries)
            if compiled!=original:raise RuntimeOperationError('management input changed before allocation')
            def snapshot():return asdict(state.mgmt) if state.mgmt else None
            def artifact(value):
                with self.store.transaction():
                    row=self.driver.original(topo.name,key)
                    row['infrastructure']=deepcopy(value);barrier.put(self.store,topo.name,row)
            progress=current.get('infrastructure')
            if progress is None:
                progress={'phase':'planning','snapshot':snapshot(),'known_snapshots':[digest(snapshot())],'attempted_hosts':[]}
                artifact(progress)
            elif digest(snapshot()) not in progress['known_snapshots']:
                raise RuntimeOperationError('management state differs from original operation checkpoints')
            else:
                state.mgmt=MgmtState(**deepcopy(progress['snapshot'])) if progress['snapshot'] else None
            def save():
                progress['snapshot']=snapshot()
                mark=digest(progress['snapshot'])
                if mark not in progress['known_snapshots']:progress['known_snapshots'].append(mark)
                artifact(progress)
                checkpoint()  # A failed save forbids the next remote mutation.
            controller=self
            class GuardedClient:
                def __init__(self,host,client):self.host,self.client=host,client
                def __getattr__(self,name):return getattr(self.client,name)
                def run_input(self,command,payload,**kwargs):
                    import json
                    try:action=json.loads(payload).get('action')
                    except (TypeError,ValueError,AttributeError):action=None
                    if action in ('provision','recover-provision','ensure','recover') or action in ('network-ensure','network-recover'):
                        controller.driver.remote(topo.name,controller.driver.original(topo.name,key),self.host,'activate')
                    return self.client.run_input(command,payload,**kwargs)
            clients={host:GuardedClient(host,client) for host,client in clients.items()}
            save()
            metadata=netsetup.prepare(resolved,schedule,clients,ips,state,save,registry=registry,
                                      generation=original['management_generation'],recover=True)
            for host,client in sorted(clients.items()):
                retried=host in progress['attempted_hosts']
                if not retried:progress['attempted_hosts'].append(host)
                save()
                receipt=netsetup.setup_mgmt_infra(resolved,schedule,client,host,ips,intent=metadata,recover=retried)
                progress.setdefault('kernel_receipts',{})[host]=receipt
                metadata.setdefault('applied_hosts',{})[host]='active';save()
            metadata.update(phase='active',provision=False);save()
            netsetup.network_action(state,clients,'recover',checkpoint=save)
            progress['proofs']=netsetup.verify_management_ready(state,clients)
            progress['phase']='infrastructure-ready';save()
            return self.driver.original(topo.name,key)

    def provision_services(self,key,lab,state,clients,checkpoint):
        """Materialize the original helper intent without releasing workloads.

        Infrastructure must already have been applied by this operation. The
        same cross-process execution lock excludes release/cancel throughout.
        """
        from ..services import management_service_runtime
        if state.lab_name!=lab or state.runtime_mode!='custom' or state.teardown_requested:
            raise RuntimeOperationError('qualified original custom lab required')
        with self.driver.provisioning(lab,key):
            original=self.driver.original(lab,key)
            bundle=original['plan'].get('services')
            infrastructure=original.get('infrastructure',{})
            if (not bundle or infrastructure.get('phase')!='infrastructure-ready'
                    or set(clients)!=set(original['targets'])
                    or digest(asdict(state.mgmt) if state.mgmt else None)!=digest(infrastructure['snapshot'])):
                raise RuntimeOperationError('original service intent and complete infrastructure checkpoint required')
            def persist(value):
                with self.store.transaction():
                    row=self.driver.original(lab,key)
                    row['services']=deepcopy(value);barrier.put(self.store,lab,row)
                checkpoint()
            progress=original.get('services') or {'phase':'preflight','intent_fingerprint':bundle['fingerprint']}
            if progress['intent_fingerprint']!=bundle['fingerprint']:
                raise RuntimeOperationError('service operation fingerprint differs')
            # Reobserve every original runtime, including hosts with no VDs,
            # before a master-local helper can change any shared resource.
            for host in sorted(original['targets']):self.driver.remote(lab,original,host,'activate')
            proofs=netsetup.verify_management_ready(state,clients)
            if set(proofs)!=set(original['targets']):raise RuntimeOperationError('all-host management proof required')
            progress['infrastructure_proofs']=proofs
            progress['preflight']=management_service_runtime.invoke(clients['master'],bundle,'preflight')
            persist(progress)
            progress['phase']='applying';persist(progress)
            # No SSH mutation follows a failed durable save. Repeat the exact
            # runtime fence check after the saves and immediately before apply.
            for host in sorted(original['targets']):self.driver.remote(lab,self.driver.original(lab,key),host,'activate')
            receipt=management_service_runtime.invoke(clients['master'],bundle,'apply')
            if (receipt.get('functional_readiness_verified') is not False
                    or not isinstance(receipt.get('external_network_id'),str)
                    or any(not isinstance(receipt.get(service),dict)
                        or set(receipt[service])!={'container_id','nonce'} for service in ('jumphost','dns'))):
                raise RuntimeOperationError('qualified service materialization receipt required')
            import re
            if (not re.fullmatch('[0-9a-f]{64}',receipt['external_network_id'])
                    or any(not re.fullmatch('[0-9a-f]{64}',receipt[s]['container_id'])
                        or not re.fullmatch('[0-9a-f]{32}',receipt[s]['nonce']) for s in ('jumphost','dns'))):
                raise RuntimeOperationError('service birth identity missing in receipt')
            progress['receipt']=receipt;progress['phase']='materialized';persist(progress)
            return self.driver.original(lab,key)

    def observe_services(self,key,lab,state,clients,checkpoint):
        """Record reobserved resources; leave functional readiness unqualified."""
        from ..services import management_service_runtime
        if state.lab_name!=lab or state.runtime_mode!='custom' or state.teardown_requested:
            raise RuntimeOperationError('qualified original custom lab required')
        with self.driver.provisioning(lab,key):
            original=self.driver.original(lab,key)
            infrastructure=original.get('infrastructure',{});progress=original.get('services',{})
            bundle=original['plan'].get('services')
            if (not bundle or progress.get('phase')!='materialized'
                    or progress.get('intent_fingerprint')!=bundle['fingerprint']
                    or infrastructure.get('phase')!='infrastructure-ready'
                    or set(clients)!=set(original['targets'])
                    or digest(asdict(state.mgmt) if state.mgmt else None)!=digest(infrastructure['snapshot'])):
                raise RuntimeOperationError('original materialized service checkpoint required')
            proofs=netsetup.verify_management_ready(state,clients)
            if set(proofs)!=set(original['targets']):raise RuntimeOperationError('all-host management proof required')
            observed=management_service_runtime.invoke(clients['master'],bundle,'observe')
            receipt=progress['receipt']
            if (observed.get('functional_readiness_verified') is not False
                    or observed.get('mutations_performed') is not False
                    or any(observed.get(k)!=receipt[k] for k in ('external_network_id','jumphost','dns'))
                    or observed.get('management_networks')!=progress['preflight']['management_networks']):
                raise RuntimeOperationError('observed services differ from original materialization')
            with self.store.transaction():
                if self.driver.original(lab,key)!=original:
                    raise RuntimeOperationError('service operation changed during observation')
                progress=deepcopy(progress)
                progress['observation']={'services':observed,'infrastructure':proofs}
                original['services']=progress;barrier.put(self.store,lab,original)
            checkpoint()
            return self.driver.original(lab,key)

    def probe_services(self,key,lab,state,clients,checkpoint):
        """Persist DNS packet and DHCP listener evidence; never release VDs."""
        from ..services import management_service_runtime
        self.observe_services(key,lab,state,clients,checkpoint)
        with self.driver.provisioning(lab,key):
            original=self.driver.original(lab,key);progress=original['services']
            if state.teardown_requested or digest(asdict(state.mgmt))!=digest(original['infrastructure']['snapshot']):
                raise RuntimeOperationError('original service infrastructure checkpoint required')
            proof=management_service_runtime.invoke(clients['master'],original['plan']['services'],'probe')
            if (proof.get('functional_readiness_verified') is not False
                    or proof.get('service_mutations_performed') is not False
                    or proof.get('observation')!=progress['observation']['services']
                    or proof.get('dns',{}).get('level')!='dns-packets'
                    or proof.get('dhcp',{}).get('level') not in ('disabled','dhcp-listeners')):
                raise RuntimeOperationError('partial service probe evidence differs')
            infrastructure=netsetup.verify_management_ready(state,clients)
            if infrastructure!=progress['observation']['infrastructure']:
                raise RuntimeOperationError('management infrastructure changed during service probes')
            with self.store.transaction():
                if self.driver.original(lab,key)!=original:
                    raise RuntimeOperationError('service operation changed during probes')
                progress=deepcopy(progress);progress['probes']=proof
                original['services']=progress;barrier.put(self.store,lab,original)
            checkpoint()
            return self.driver.original(lab,key)

    def qualify_probe_lifecycle(self,key,lab,state,clients,checkpoint):
        return self._qualify_probes(key,lab,state,clients,checkpoint,packets=False)

    def qualify_probe_packets(self,key,lab,state,clients,checkpoint):
        return self._qualify_probes(key,lab,state,clients,checkpoint,packets=True)

    def qualify_dns_clients(self,key,lab,state,clients,checkpoint):
        return self._qualify_probes(key,lab,state,clients,checkpoint,packets=True,dns=True)

    def qualify_routing(self,key,lab,state,clients,checkpoint):
        from .management_routing_prepare import qualify
        return qualify(self,key,lab,state,clients,checkpoint)

    def release_network_services(self,key,lab,state,clients):
        """Reobserve original service qualifications before releasing workloads.

        Guest readiness and application access are deliberately separate. This
        does not allocate probes, repair services or replace the sealed intent.
        """
        from .management_readiness import observe
        return self.driver.release(lab,key,lambda plan,targets:observe(self,key,lab,state,clients))

    def _qualify_probes(self,key,lab,state,clients,checkpoint,*,packets,dns=False):
        """Sequential, original endpoint/packet attempts; never release VDs."""
        from ..services import management_probe_runtime,management_service_runtime
        self.observe_services(key,lab,state,clients,checkpoint)
        with self.driver.provisioning(lab,key):
            original=self.driver.original(lab,key);bundle=original['plan']['services']
            if 'packet_probe_identities' not in bundle or state.management_plan!=bundle['management_plan']:
                raise RuntimeOperationError('original infrastructure probe identity model required')
            observed=netsetup.verify_management_ready(state,clients)
            field='dns_client_probes' if dns else 'packet_probes' if packets else 'probe_lifecycle'
            server_profile=None
            if packets:
                server_profile=management_service_runtime.invoke(clients['master'],bundle,'packet_profiles')
                if (server_profile.get('observation',{}).get('observation')!=original['services']['observation']['services']
                        or server_profile.get('service_mutations_performed') is not False
                        or set(server_profile.get('servers',{}))!=set(bundle['packet_probe_identities'])):
                    raise RuntimeOperationError('original packet server proof differs')
            from .management_probe_requests import compile_requests
            requests=compile_requests(original,observed,server_profile,packets=packets,dns=dns)
            progress=original.get(field)
            if progress is None:progress={'phase':'applying','requests':requests,'entries':{},'endpoint_lifecycle_only':not packets,'server_profile':server_profile}
            elif progress.get('server_profile')!=server_profile:raise RuntimeOperationError('packet server generation changed')
            elif progress['requests']!=requests:raise RuntimeOperationError('original probe lifecycle requests changed')
            def save():
                with self.store.transaction():
                    row=self.driver.original(lab,key)
                    row[field]=deepcopy(progress);barrier.put(self.store,lab,row)
                checkpoint()
            # Full read-only preflight precedes the first allocation and every
            # recovery. The execution lock excludes release/cancellation.
            for request in requests:
                management_probe_runtime.invoke(clients[request['host']],request,'preflight')
            save()
            for request in requests:
                request_id=request['request_id'];host=request['host']
                entry=progress['entries'].setdefault(request_id,{'phase':'pending'})
                if entry['phase'] not in ('cleanup_pending','cleaned'):
                    entry['phase']='applying';save()
                    for target in sorted(original['targets']):self.driver.remote(lab,self.driver.original(lab,key),target,'activate')
                    if entry.get('birth') is not None:
                        active=management_probe_runtime.invoke(clients[host],request,'inspect',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                    else:
                        active=management_probe_runtime.invoke(clients[host],request,'ensure')
                    proof=active.get('resource_proof',{})
                    management_probe_runtime.validate_birth(request,proof)
                    if entry.get('birth') is not None and entry['birth']!=proof:
                        raise RuntimeOperationError('original checkpointed probe birth differs')
                    if entry.get('birth') is None:entry['birth']=deepcopy(proof);save()
                    if packets:
                        prepared=management_probe_runtime.invoke(clients[host],request,'prepare-packets',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                        identity=prepared.get('execution')
                        management_probe_runtime.validate_execution(request,entry['birth'],identity)
                        if entry.get('execution') is not None and entry['execution']!=identity:raise RuntimeOperationError('original packet exec differs')
                        if entry.get('execution') is None:entry['execution']=deepcopy(identity);save()
                        response=management_probe_runtime.invoke(clients[host],request,'packets',expected_birth=entry['birth'],expected_execution=entry['execution'])
                        if response.get('resource_proof')!=entry['birth']:raise RuntimeOperationError('packet probe birth differs')
                        management_probe_runtime.validate_packets(request,response.get('packet_result'))
                        if management_service_runtime.invoke(clients['master'],bundle,'packet_profiles')!=server_profile:
                            raise RuntimeOperationError('original DHCP service changed during packet probe')
                        entry['packets']=response['packet_result'];save()
                    entry['phase']='cleanup_pending';save()
                if entry['phase']=='cleanup_pending':
                    for target in sorted(original['targets']):self.driver.remote(lab,self.driver.original(lab,key),target,'activate')
                    cleaned=management_probe_runtime.invoke(clients[host],request,'cleanup',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                    if cleaned.get('resource_proof')!=entry['birth']:
                        raise RuntimeOperationError('probe cleanup original birth differs')
                    entry['phase']='cleaned';entry['receipt']=cleaned;save()
                verified=management_probe_runtime.invoke(clients[host],request,'verify-cleaned',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                if verified!=entry['receipt']:raise RuntimeOperationError('probe cleanup proof changed')
            progress['phase']='completed';save()
            return self.driver.original(lab,key)
