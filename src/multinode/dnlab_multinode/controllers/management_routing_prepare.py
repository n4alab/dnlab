"""Paired infrastructure probes under the existing offline coordinator fence."""
from copy import deepcopy
from itertools import combinations,product

from ..services import management_probe_runtime as probes,management_service_runtime as services
from ..services import management_barrier as barrier,netsetup
from ..services.runtime_operations import RuntimeOperationError,digest


def requests(original,observed,servers):
    bundle=original['plan']['services'];model=bundle['management_plan'];identities=bundle['packet_probe_identities']
    if set(identities)!=set(model['networks']):
        raise RuntimeOperationError('routing probes require original infrastructure reservations on every management')
    result=[]
    for left,right in combinations(sorted(identities),2):
        for hosts in product(sorted(original['targets']),repeat=2):
            pair=digest([original['barrier_id'],'routed-pair',left,right,*hosts]);rows=[]
            for side,segment in enumerate((left,right)):
                host=hosts[side];peer=(right,left)[side];identity=identities[segment]
                network=observed[host]['networks']['proof']['networks'][segment]
                cfg=model['networks'][segment];server=servers[segment]
                addresses={'4':identity['ipv4']};remote={'4':identities[peer]['ipv4']}
                if identity['ipv6'] and identities[peer]['ipv6']:
                    addresses['6']=identity['ipv6'];remote['6']=identities[peer]['ipv6']
                profile={'mode':'routed-pair','interface':'probe0','client_mac':identity['mac'],
                    'server_mac':server['mac'],'server_ip':cfg['ipv4_gw'],
                    'server_ipv6':cfg['ipv6_gw'] if '6' in addresses else None,
                    'server_link_local':server['link_local'] if '6' in addresses else None,
                    'addresses':addresses,'peer_addresses':remote,'peer_segment':peer,'token':pair,
                    'side':side,'port':49152+int(pair[:4],16)%16384}
                rows.append({'lab':bundle['lab'],'segment':segment,'host':host,
                    'operation_id':original['barrier_id'],'request_id':digest([pair,side])[:32],
                    'image':bundle['jumphost']['image'],'identity':deepcopy(identity),
                    'attachment':deepcopy(bundle['attachments'][segment]['attachment']),
                    'management_intent':deepcopy(original['plan']['hosts'][host]['segments'][segment]['network']),
                    'management_generation':original['plan']['management_generation'],
                    'network_id':network['id'],'network_nonce':network['nonce'],'packet_profile':profile})
            result.append({'id':pair,'requests':rows})
    return result


def qualify(controller,key,lab,state,clients,checkpoint):
    controller.observe_services(key,lab,state,clients,checkpoint)
    driver=controller.driver
    with driver.provisioning(lab,key):
        original=driver.original(lab,key);bundle=original['plan']['services']
        if state.management_plan!=bundle.get('management_plan'):
            raise RuntimeOperationError('original routing identity model required')
        infrastructure=netsetup.verify_management_ready(state,clients)
        profile=services.invoke(clients['master'],bundle,'packet_profiles')
        if profile.get('observation',{}).get('observation')!=original['services']['observation']['services']:
            raise RuntimeOperationError('routing service generation differs')
        def observe_router():
            snapshot=services.invoke(clients['master'],bundle,'routing_snapshot')
            if (snapshot.get('observation')!=original['services']['observation']['services']
                    or snapshot.get('validation',{}).get('status')!='accepted'
                    or snapshot.get('service_mutations_performed') is not False):
                raise RuntimeOperationError('original routing prerequisites unavailable')
            return snapshot
        snapshot=observe_router();pairs=requests(original,infrastructure,profile['servers'])
        progress=original.get('routing_probes')
        if progress is None:
            progress={'phase':'applying','pairs':pairs,'entries':{},'server_profile':profile,
                      'routing_snapshot':snapshot,'packet_forwarding_verified':False}
        elif progress['pairs']!=pairs or progress['server_profile']!=profile:
            raise RuntimeOperationError('original routing pair or service generation changed')
        def save():
            with controller.store.transaction():
                row=driver.original(lab,key);row['routing_probes']=deepcopy(progress)
                barrier.put(controller.store,lab,row)
            checkpoint()
        save()
        for pair in pairs:
            entries=[progress['entries'].setdefault(r['request_id'],{'phase':'pending'}) for r in pair['requests']]
            if all(entry['phase']=='cleaned' for entry in entries):
                for request,entry in zip(pair['requests'],entries):
                    receipt=probes.invoke(clients[request['host']],request,'verify-cleaned',
                        expected_birth=entry['birth'],expected_execution=entry['execution'])
                    if receipt!=entry['receipt']:raise RuntimeOperationError('routing probe cleanup proof changed')
                continue
            # Every touched endpoint is preflighted before the pair allocates.
            # Segments differ, so the same reservation is never active twice.
            netsetup.verify_management_ready(state,clients);observe_router()
            for request in pair['requests']:probes.invoke(clients[request['host']],request,'preflight')
            for host in sorted(original['targets']):driver.remote(lab,driver.original(lab,key),host,'activate')
            for request,entry in zip(pair['requests'],entries):
                if entry['phase'] in ('cleanup_pending','cleaned'):continue
                client=clients[request['host']]
                if entry.get('birth'):
                    result=probes.invoke(client,request,'inspect',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                else:
                    result=probes.invoke(client,request,'ensure');entry['birth']=deepcopy(result['resource_proof']);save()
                prepared=probes.invoke(client,request,'prepare-packets',expected_birth=entry['birth'],expected_execution=entry.get('execution'))
                identity=prepared['execution'];probes.validate_execution(request,entry['birth'],identity)
                if entry.get('execution') is not None and entry['execution']!=identity:
                    raise RuntimeOperationError('original routing exec changed')
                entry['execution']=deepcopy(identity);entry['phase']='prepared';save()
            for request,entry in zip(pair['requests'],entries):
                if entry['phase'] in ('cleanup_pending','cleaned'):continue
                probes.invoke(clients[request['host']],request,'start-packets',
                    expected_birth=entry['birth'],expected_execution=entry['execution'])
            for request,entry in zip(pair['requests'],entries):
                if entry['phase'] in ('cleanup_pending','cleaned'):continue
                result=probes.invoke(clients[request['host']],request,'packets',
                    expected_birth=entry['birth'],expected_execution=entry['execution'])
                probes.validate_packets(request,result['packet_result'])
                entry['packets']=deepcopy(result['packet_result']);entry['phase']='packets-completed';save()
            # Do not remove either peer until both original execs have exited.
            if any(entry['phase'] not in ('packets-completed','cleanup_pending','cleaned') for entry in entries):
                raise RuntimeOperationError('both routing peers must complete before cleanup')
            observe_router()
            if services.invoke(clients['master'],bundle,'packet_profiles')!=profile:
                raise RuntimeOperationError('original routing service changed during packets')
            for request,entry in zip(pair['requests'],entries):
                if entry['phase']!='cleaned':
                    entry['phase']='cleanup_pending';save()
                    receipt=probes.invoke(clients[request['host']],request,'cleanup',
                        expected_birth=entry['birth'],expected_execution=entry['execution'])
                    entry['receipt']=deepcopy(receipt);entry['phase']='cleaned';save()
                receipt=probes.invoke(clients[request['host']],request,'verify-cleaned',
                    expected_birth=entry['birth'],expected_execution=entry['execution'])
                if receipt!=entry['receipt']:raise RuntimeOperationError('routing cleanup proof changed')
        progress['phase']='completed';progress['packet_forwarding_verified']=bool(pairs);save()
        return driver.original(lab,key)
