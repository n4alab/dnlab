"""Frozen native VD inventory publication, resumed without another lifecycle."""
from copy import deepcopy
import re

from . import jumphost,native_public as native
from .relay_resolution import qualify_relay
from .runtime_operations import digest

CAPABILITY='qualified-relay-inventory-v1'


def selected(state,exclude):
    value=deepcopy(state)
    if exclude is not None:value.node_runtime.pop(exclude,None)
    return value


def workloads(state,store,clients):
    native.backend(state);proofs={};relays={}
    for node,runtime in sorted(state.node_runtime.items()):
        original=native.source(store,state,node)
        view,candidate=native.inspect_owned(store,state,node,native.client_for(clients[runtime.host],original))
        b=runtime.runtime_binding;birth=view.get('workload') or {}
        wanted={'running':'running','stopped':'absent'}.get(view.get('committed_state'))
        if (view.get('operation') is not None or view.get('container_state')!=wanted or wanted is None
                or birth.get('container_id')!=b['container_id']
                or candidate['request_id']!=original['request_id']):
            raise RuntimeError('native inventory workload is not committed and qualified')
        proofs[node]={'binding':deepcopy(b),'host':runtime.host,'container':runtime.container,
                      'committed_state':view['committed_state'],'revision':view['revision']}
        if runtime.host not in relays:
            relay=state.runtime_relays.get(runtime.host)
            if relay is None:raise RuntimeError('native inventory relay missing')
            relays[runtime.host]=qualify_relay(clients[runtime.host],state,runtime.host,relay)
    return proofs,relays


def jumphost_proof(state,record):
    jh=state.jumphost;config=record.get('config',{})
    if (not jh or config.get('lab')!=state.lab_name or config.get('name')!=jh.container
            or config.get('generation')!=jh.generation
            or not re.fullmatch('[0-9a-f]{64}',str(record.get('container_id','')))):
        raise RuntimeError('native inventory jumphost generation differs')
    labels=record.get('image',{}).get('Config',{}).get('Labels') or {}
    if CAPABILITY not in labels.get('io.dnlab.jumphost.capabilities','').split(','):
        raise RuntimeError('jumphost image lacks qualified relay inventory capability')
    return {k:deepcopy(record[k]) for k in ('config','nonce','container_id','image','context')}


def prepare(state,store,clients,request_id,exclude=None):
    scope=selected(state,exclude);nodes,relays=workloads(scope,store,clients)
    jh=state.jumphost;record=jumphost._guard(clients[jh.node],state.lab_name,'read')
    proof=jumphost_proof(state,record)
    if record.get('phase')!='active' or record.get('inventory_operation'):
        raise RuntimeError('original jumphost inventory recovery required')
    mapping={r.node:r.container for r in scope.node_runtime.values()}
    relay_map=jumphost.relay_inventory_from_state(scope,verified_bindings={k:r.runtime_binding for k,r in scope.node_runtime.items()})
    vds,rows=jumphost.render_relay_inventory(mapping,relay_map)
    desired={'lab':state.lab_name,'generation':jh.generation,'container_id':record['container_id'],
             'request_id':digest(['native-inventory-v1',state.lab_name,request_id])[:32],
             'vds':vds,'relays':rows,'motd':jumphost._render_inventory_motd(state.lab_name,sorted(mapping))}
    manifest={'lab':state.lab_name,'host':jh.node,'exclude':exclude,'nodes':nodes,'relays':relays,
              'jumphost':proof,'previous':deepcopy(record.get('inventory_current')),'desired':desired}
    return {'phase':'pending','manifest':manifest,'fingerprint':digest(manifest)}


def apply(state,store,clients,intent):
    manifest=intent['manifest']
    if (intent.get('fingerprint')!=digest(manifest) or manifest['lab']!=state.lab_name
            or not state.jumphost or manifest['host']!=state.jumphost.node):
        raise RuntimeError('native inventory publication intent differs')
    nodes,relays=workloads(selected(state,manifest['exclude']),store,clients)
    if nodes!=manifest['nodes'] or relays!=manifest['relays']:
        raise RuntimeError('native inventory consumers changed; original publication retained')
    client=clients[manifest['host']];request=manifest['desired']
    record=jumphost._guard(client,state.lab_name,'read')
    if jumphost_proof(state,record)!=manifest['jumphost']:
        raise RuntimeError('native inventory original jumphost changed')
    op=record.get('inventory_operation')
    if op:
        if (record.get('action')!='inventory' or op.get('desired')!=request
                or op.get('previous')!=manifest['previous']):
            raise RuntimeError('another jumphost inventory operation requires recovery')
        result=jumphost._guard(client,state.lab_name,'recover')
    else:
        if record.get('phase')!='active' or record.get('inventory_current') not in (manifest['previous'],request):
            raise RuntimeError('jumphost inventory was superseded')
        result=jumphost._guard(client,state.lab_name,'inventory-refresh',request)
    if (jumphost_proof(state,result)!=manifest['jumphost'] or result.get('phase')!='active'
            or result.get('inventory_operation') or result.get('inventory_current')!=request):
        raise RuntimeError('native inventory publication not verified')
