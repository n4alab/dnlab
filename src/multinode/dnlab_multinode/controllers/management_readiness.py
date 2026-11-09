"""Read-only aggregation of original management network-service qualifications.

This admits workloads to provisioned networks; guest/NOS readiness, GUI login,
public TLS and guest application reachability remain separate contracts.
"""
from copy import deepcopy
from dataclasses import asdict
from ..services import management_barrier as barrier,netsetup
from ..services import management_probe_runtime as probes,management_service_runtime as services
from ..services.runtime_operations import RuntimeOperationError,digest
from .management_probe_requests import compile_requests
from .management_routing_prepare import requests as routing_requests


def observe(controller,key,lab,state,clients):
    original=controller.driver.original(lab,key)
    if (state.lab_name!=lab or state.runtime_mode!='custom' or state.teardown_requested
            or original['phase'] not in ('provisioning','releasing')
            or set(clients)!=set(original['targets'])):
        raise RuntimeOperationError('original sealed management readiness context required')
    try:return _observe(controller,key,lab,state,clients,original)
    except (KeyError,TypeError,ValueError) as error:
        raise RuntimeOperationError('complete original management qualification evidence required') from error


def _observe(controller,key,lab,state,clients,original):
    bundle=original['plan']['services'];progress=original['services'];infrastructure=original['infrastructure']
    if (infrastructure['phase']!='infrastructure-ready' or progress['phase']!='materialized'
            or progress['intent_fingerprint']!=bundle['fingerprint']
            or state.management_plan!=bundle['management_plan']
            or digest(asdict(state.mgmt))!=digest(infrastructure['snapshot'])):
        raise RuntimeOperationError('original management and service checkpoints differ')
    current=netsetup.verify_management_ready(state,clients)
    saved=progress['observation']
    if current!=saved['infrastructure'] or set(current)!=set(original['targets']):
        raise RuntimeOperationError('original all-host management resources differ')
    observed=services.invoke(clients['master'],bundle,'observe')
    if observed!=saved['services'] or observed.get('mutations_performed') is not False:
        raise RuntimeOperationError('original management service generations differ')
    partial=progress['probes']
    if (partial['observation']!=observed or partial['dns']['level']!='dns-packets'
            or partial['dhcp']['level'] not in ('disabled','dhcp-listeners')
            or partial.get('service_mutations_performed') is not False):
        raise RuntimeOperationError('original central service probe evidence differs')
    profile=services.invoke(clients['master'],bundle,'packet_profiles')
    if (profile['observation']['observation']!=observed
            or profile.get('service_mutations_performed') is not False
            or set(profile['servers'])!=set(bundle['management_plan']['networks'])):
        raise RuntimeOperationError('current management packet service profile differs')
    expected={
        'packet_probes':compile_requests(original,current,profile,packets=True),
        'dns_client_probes':compile_requests(original,current,profile,packets=True,dns=True)}
    pairs=routing_requests(original,current,profile['servers'])
    routed=original['routing_probes']
    if (routed['pairs']!=pairs or routed['packet_forwarding_verified'] is not bool(pairs)):
        raise RuntimeOperationError('complete original routed-pair coverage required')
    expected['routing_probes']=[request for pair in pairs for request in pair['requests']]
    if 'probe_lifecycle' in original:
        expected['probe_lifecycle']=compile_requests(original,current,None,packets=False)
    attempts={host:{} for host in clients}
    for field,requests in expected.items():
        stage=original[field];packets=field!='probe_lifecycle'
        if (stage['phase']!='completed' or field!='routing_probes' and stage['requests']!=requests
                or packets and stage['server_profile']!=profile
                or set(stage['entries'])!={q['request_id'] for q in requests}):
            raise RuntimeOperationError('complete original '+field+' qualification required')
        for request in requests:
            entry=stage['entries'][request['request_id']]
            if entry['phase']!='cleaned' or entry['receipt'].get('cleanup_verified') is not True:
                raise RuntimeOperationError('verified original management probe cleanup required')
            probes.validate_birth(request,entry['birth'])
            if packets:
                probes.validate_execution(request,entry['birth'],entry['execution'])
                probes.validate_packets(request,entry['packets'])
            receipt=probes.invoke(clients[request['host']],request,'verify-cleaned',
                expected_birth=entry['birth'],expected_execution=entry.get('execution'))
            if receipt!=entry['receipt']:
                raise RuntimeOperationError('original management probe cleanup receipt differs')
            attempts[request['host']][request['request_id']]=digest({'field':field,'request':request,'entry':entry})
    routing=services.invoke(clients['master'],bundle,'routing_snapshot')
    if (routing['observation']!=observed or routing['validation']['status']!='accepted'
            or routing.get('service_mutations_performed') is not False):
        raise RuntimeOperationError('current management routing prerequisites differ')
    # Detect replacement during the sequential observations without new packets.
    if (netsetup.verify_management_ready(state,clients)!=current
            or services.invoke(clients['master'],bundle,'packet_profiles')!=profile
            or controller.driver.original(lab,key)!=original):
        raise RuntimeOperationError('management readiness changed during observation')
    return {'plan_fingerprint':original['plan_fingerprint'],'hosts':{
        host:{'scope':'management-network-services-v1','infrastructure':deepcopy(current[host]),
              'service_observation':deepcopy(observed),'packet_service_profile':deepcopy(profile),
              'routing_validation':deepcopy(routing['validation']),'qualified_attempts':attempts[host]}
        for host in sorted(clients)}}
