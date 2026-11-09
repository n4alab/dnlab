"""Coordinator boundary for journaled host management infrastructure.

The existing scheduler/placement is authoritative. This layer only reserves
VNIs, checks every participating host and tracks local worker operations.
"""
import copy
import json
from pathlib import Path
import shlex
import re
import uuid

from .management_host import ManagementError, digest, validate
from .paths import PATHS
from .realnet_vni import Registry, identity_key, snapshots
from ..utils import naming

NETWORK_SOURCE = Path(__file__).with_name('management_network_host.py').read_text()
PROGRAM = "_ns={'__name__':'management_network_worker'}\nexec(" + repr(NETWORK_SOURCE) + ",_ns)\n_NetworkGuard=_ns['NetworkGuard']\n" + Path(__file__).with_name('management_host.py').read_text()


def invoke(client, action, plan, *, segments=None, networks=None, operation_id=None):
    payload = dict(action=action, plan=plan, directory=PATHS.management_journal_dir)
    if segments is not None: payload['segments'] = segments
    if operation_id is not None: payload['operation_id']=operation_id
    if networks is not None:
        from .mgmt_network import PLUGIN_STATE
        payload.update(networks=networks,socket_path=PATHS.docker_socket.removeprefix('unix://'),plugin_path=PLUGIN_STATE)
    value = json.loads(client.run_input(shlex.join(['python3', '-c', PROGRAM]), json.dumps(payload), timeout=180))
    network_action = action.removeprefix('network-') if networks is not None else None
    expected = {'ensure': 'active', 'recover': ('active', 'cleaned'), 'cleanup': 'cleaned',
                'provision': 'active', 'recover-provision': 'active', 'preflight-provision': 'verified', 'verify-cleaned': 'cleaned', 'verify-ready': 'ready', 'preflight': 'verified', 'preflight-cleanup': 'verified', 'read': 'read'}.get(action)
    if networks is not None: expected = {'preflight':'verified','preflight-cleanup':'verified','preflight-teardown':'verified','preflight-restore':'verified','preflight-recover':'verified','preflight-provision-recover':'verified','ensure':'active','recover':('active','cleaned'),'restore':'active','mark-used':'active','cleanup':'cleaned','verify-cleaned':'cleaned','verify-ready':'ready'}[network_action]
    if value.get('status') not in (expected if isinstance(expected, tuple) else (expected,)) or value.get('plan') != digest(plan):
        raise ManagementError('invalid management worker acknowledgement')
    if networks is not None and value.get('networks') != networks: raise ManagementError('network acknowledgement definition differs')
    if action in ('verify-ready', 'network-verify-ready'):
        if not isinstance(value.get('proof'), dict) or not value['proof'] or value.get('fingerprint') != digest(value['proof']):
            raise ManagementError('management readiness proof differs')
    return value


def checked(state, clients):
    value = state.mgmt.infrastructure if state.mgmt else None
    if not value or value.get('schema') != 1 or not value.get('plans'):
        raise ManagementError('legacy management infrastructure requires explicit qualification')
    if set(value['plans']) - clients.keys(): raise ManagementError('complete management preflight: host unavailable')
    for host, plan in value['plans'].items():
        validate(plan)
        if set(plan['segments']) != set(value.get('reservations', {})):
            raise ManagementError('management segment reservation inventory differs')
        for segment, config in plan['segments'].items():
            row = value['reservations'][segment]
            if row.get('key') != identity_key([state.lab_name, 'management', segment, 'multipoint']) or row.get('vni') != config['vni']:
                raise ManagementError('management reservation identity differs')
        if plan['lab'] != state.lab_name or plan['generation'] != value['generation']:
            raise ManagementError('management coordinator identity differs')
    return value


def prepare(topo, schedule, clients, ips, state, checkpoint, *, registry=None, generation=None, recover=False):
    """Persist intent/reservations, then complete ALL read-only host preflights."""
    from ..models.state import MgmtState
    if set(ips) != set(clients): raise ManagementError('management host inventory incomplete')
    previous = state.mgmt.infrastructure if state.mgmt else {}
    if state.mgmt and not previous: raise ManagementError('management legacy adoption refused')
    if generation is not None and (not isinstance(generation, str) or not re.fullmatch('[0-9a-f]{32}', generation)
            or previous and previous.get('generation') != generation):
        raise ManagementError('management generation differs from admitted intent')
    generation = generation or previous.get('generation') or uuid.uuid4().hex
    segments = topo.management_networks or {'default': topo.mgmt}
    targets = {}
    for key, cfg in segments.items():
        vx = naming.mgmt_vxlan_iface(topo.name) if key == 'default' else 'vm' + digest([topo.name, key])[:13]
        targets[key] = {host: dict(name=vx, bridge=cfg.bridge, local=ip, remotes=sorted(v for h, v in ips.items() if h != host),
                                  underlay=topo.underlay_iface, dstport=4789) for host, ip in ips.items()}
    if not previous:
        state.mgmt = MgmtState(subnet=topo.mgmt.ipv4_subnet, gateway=topo.mgmt.ipv4_gw, bridge=topo.mgmt.bridge,
            vrf=naming.vrf_name(topo.name), vxlan_id=0, vxlan_iface=naming.mgmt_vxlan_iface(topo.name), network=topo.mgmt.network,
            network_driver='dnlab-vrf', ipam_driver='dnlab-vrf')
        state.mgmt.infrastructure = dict(schema=1, generation=generation, phase='planning', plans={}, reservations={}, provision=True)
    metadata = state.mgmt.infrastructure
    checkpoint()  # Failure here forbids even a durable VNI reservation.
    proofs = {}
    for host, plan in metadata['plans'].items():
        if host not in clients: raise ManagementError('management host unavailable')
        proofs[host] = invoke(clients[host], 'read', plan)['record']
    requests = [dict(identity=[topo.name, 'management', key, 'multipoint'], targets=value,
                     previous=metadata['reservations'].get(key), proofs=proofs) for key, value in targets.items()]
    allocator = registry or Registry()
    allocated = allocator.reserve(requests, lambda hosts: snapshots(clients, hosts))
    plans = {host: dict(lab=topo.name, generation=generation, vrf=naming.vrf_name(topo.name), table=schedule.vrf_table_id, segments={}) for host in clients}
    for key, cfg in segments.items():
        reservation = allocated[identity_key([topo.name, 'management', key, 'multipoint'])]
        metadata['reservations'][key] = reservation
        for host in plans:
            t = targets[key][host]
            plans[host]['segments'][key] = dict(bridge=cfg.bridge, vxlan=t['name'], vni=reservation['vni'], underlay=t['underlay'],
                local=t['local'], remotes=t['remotes'], address=(cfg.docker_ipv4_gw or cfg.ipv4_gw) + '/' + cfg.ipv4_subnet.split('/')[1])
    # Existing definitions may only grow; no implicit reconfiguration/removal.
    for host, old in metadata['plans'].items():
        if host not in plans or any(
                k not in plans[host]['segments']
                or {x:y for x,y in plans[host]['segments'][k].items() if x != 'remotes'} != {x:y for x,y in v.items() if x != 'remotes'}
                or not set(v['remotes']) <= set(plans[host]['segments'][k]['remotes']) for k, v in old['segments'].items()):
            raise ManagementError('management topology change requires a tracked operation')
    metadata.update(plans=plans, phase='preflight'); checkpoint()
    for host, plan in sorted(plans.items()): invoke(clients[host], 'preflight-provision' if metadata.get('provision') else 'preflight', plan)
    prepare_networks(topo,state,clients,checkpoint,recover=recover)
    metadata['phase'] = 'applying'; checkpoint()
    schedule.mgmt_vxlan_id = state.mgmt.vxlan_id = metadata['reservations']['default']['vni']
    return metadata


def setup_mgmt_infra(topo, plan, client, host_name, all_host_ips, *, intent=None, recover=False):
    """Compatible call boundary; allocation requires an admitted durable intent."""
    if not intent or host_name not in intent.get('plans', {}):
        raise ManagementError('management setup requires complete coordinator preflight')
    action = ('recover-provision' if recover else 'provision') if intent.get('provision') else ('recover' if recover else 'ensure')
    return invoke(client, action, intent['plans'][host_name])


def verify_management_ready(state, clients):
    """Return complete observed infrastructure proofs, not service readiness."""
    metadata = checked(state, clients)
    if set(metadata.get('networks', {})) != set(metadata['plans']):
        raise ManagementError('complete management network definitions required')
    proofs = {}
    for host, plan in sorted(metadata['plans'].items()):
        proofs[host] = dict(kernel=invoke(clients[host], 'verify-ready', plan),
            networks=invoke(clients[host], 'network-verify-ready', plan, networks=metadata['networks'][host]))
    return proofs


def preflight_management(state, clients, *, cleanup=False):
    metadata = checked(state, clients)
    for host, plan in sorted(metadata['plans'].items()):
        invoke(clients[host], 'preflight-cleanup' if cleanup else 'preflight', plan)
    if metadata.get('networks'):
        network_preflight(state,clients,cleanup=cleanup,teardown=state.teardown_requested)
    return metadata


def teardown_mgmt_infra(lab_name, bridge, client, host_name, *, intent=None):
    if not intent or host_name not in intent.get('plans', {}):
        raise ManagementError('management cleanup requires durable birth proof; no name-only deletion')
    plan = intent['plans'][host_name]
    if plan['lab'] != lab_name or bridge not in {s['bridge'] for s in plan['segments'].values()}:
        raise ManagementError('management cleanup scope differs')
    return invoke(client, 'cleanup', plan)


def verify_management_cleaned(state, clients):
    metadata = checked(state, clients)
    if metadata.get('networks'):
        for host,plan in sorted(metadata['plans'].items()):invoke(clients[host],'network-verify-cleaned',plan,networks=metadata['networks'][host])
    for host, plan in sorted(metadata['plans'].items()): invoke(clients[host], 'verify-cleaned', plan)


def release_management(state, clients, *, registry=None, checkpoint=lambda: None):
    metadata = checked(state, clients)
    (registry or Registry()).release(list(metadata['reservations'].values()), lambda: verify_management_cleaned(state, clients))
    metadata['phase'] = 'cleaned'; checkpoint()


def destroy_management(state, clients, *, checkpoint=lambda: None, registry=None):
    metadata = preflight_management(state, clients, cleanup=True)
    metadata['phase'] = 'cleanup_pending'; checkpoint()
    if metadata.get('networks'): network_action(state,clients,'cleanup',checkpoint=checkpoint)
    for host, plan in sorted(metadata['plans'].items()):
        invoke(clients[host], 'cleanup', plan)
        metadata.setdefault('cleanup_hosts', {})[host] = 'cleaned'; checkpoint()
    release_management(state, clients, registry=registry, checkpoint=checkpoint)


def prepare_networks(topo,state,clients,checkpoint,*,recover=False):
    from .mgmt_network import _expected_network
    metadata = checked(state,clients); definitions = {}
    for host in metadata['plans']:
        definitions[host] = {}
        for key,cfg in (topo.management_networks or {'default':topo.mgmt}).items():
            selected = copy.copy(topo); selected.mgmt = cfg
            definitions[host][key] = _expected_network(selected,host)
    if metadata.get('networks'):
        for host,segments in metadata['networks'].items():
            if any(definitions.get(host,{}).get(k) != v for k,v in segments.items()):
                raise ManagementError('network definition changed; explicit operation required')
    metadata['networks'] = definitions;checkpoint()
    network_preflight(state,clients,provision_recover=recover)
    return definitions


def network_targets(metadata,targets=None,host=None):
    definitions=metadata.get('networks',{})
    if targets is None:
        hosts=sorted(definitions) if host is None else [host]
        if any(h not in definitions for h in hosts):raise ManagementError('unknown management network host')
        return {h:sorted(definitions[h]) for h in hosts}
    if host is not None or not isinstance(targets,dict) or not targets:raise ManagementError('explicit network targets required')
    result={}
    for name,segments in targets.items():
        if (name not in definitions or not isinstance(segments,list) or not segments
                or any(not isinstance(k,str) for k in segments) or len(set(segments))!=len(segments)
                or not set(segments)<=definitions[name].keys()):raise ManagementError('unknown management network target')
        result[name]=sorted(segments)
    return result


def network_preflight(state,clients,*,cleanup=False,teardown=False,restore=False,recover=False,provision_recover=False,operation_id=None,targets=None):
    metadata=checked(state,clients)
    if set(metadata.get('networks',{})) != set(metadata['plans']):
        raise ManagementError('qualified Docker network definitions required')
    selected=network_targets(metadata,targets)
    for host,plan in sorted(metadata['plans'].items()):
        definitions=metadata['networks'][host];keys=set(selected.get(host,[]))
        action = 'preflight-provision-recover' if provision_recover else ('preflight-cleanup' if cleanup else ('preflight-restore' if restore else ('preflight-recover' if recover else ('preflight-teardown' if teardown else 'preflight'))))
        # Unaffected hosts/segments are verified too, without requesting repair,
        # endpoint removal, or a new generation on an intact network.
        for subset,mode in (({k:v for k,v in definitions.items() if k not in keys},'preflight'),
                            ({k:v for k,v in definitions.items() if k in keys},action)):
            if subset:invoke(clients[host],'network-'+mode,plan,networks=subset,operation_id=operation_id)
    return metadata


def network_action(state,clients,action,*,checkpoint=lambda:None,host=None,operation_id=None,targets=None):
    if operation_id is not None and (not isinstance(operation_id,str) or not re.fullmatch('[0-9a-f]{32}',operation_id)):
        raise ManagementError('network operation must be a UUID hex token')
    metadata=checked(state,clients);previous=metadata.get('network_operation',{})
    restoring=action=='restore' or action=='recover' and previous.get('action')=='restore' and previous.get('phase')=='pending'
    if restoring and targets is None and host is None and previous.get('action')=='restore' and previous.get('phase')=='pending':targets=previous.get('targets')
    selected=network_targets(metadata,targets,host)
    if restoring:
        action='restore'
        if operation_id is None and previous.get('action')=='restore' and previous.get('phase')=='pending':
            if previous.get('targets')!=selected:raise ManagementError('pending restore target set differs')
            operation_id=previous['id']
        operation_id=operation_id or uuid.uuid4().hex
        if previous.get('id')==operation_id and previous.get('targets')!=selected:
            raise ManagementError('restore request targets are immutable')
        metadata['network_operation']=dict(id=operation_id,action='restore',targets=selected,phase='pending');checkpoint()
    metadata=network_preflight(state,clients,cleanup=action in ('cleanup','verify-cleaned'),restore=restoring,recover=action=='recover',operation_id=operation_id,targets=selected)
    metadata['network_phase']=action;checkpoint()
    for name,segments in sorted(selected.items()):
        definitions={k:metadata['networks'][name][k] for k in segments}
        receipt=invoke(clients[name],'network-'+action,metadata['plans'][name],networks=definitions,operation_id=operation_id)
        statuses=metadata.setdefault('network_segments',{}).setdefault(name,{})
        for segment in segments:statuses[segment]='cleaned' if receipt['status']=='cleaned' else 'active'
        metadata.setdefault('network_hosts',{})[name]='cleaned' if all(statuses.get(k)=='cleaned' for k in metadata['networks'][name]) else 'active'
        checkpoint()
    phases=[metadata.get('network_hosts',{}).get(name) for name in metadata['plans']]
    metadata['network_phase']='cleaned' if all(value=='cleaned' for value in phases) else ('cleanup_pending' if 'cleaned' in phases else 'active')
    if restoring:metadata['network_operation']['phase']='completed'
    checkpoint()
