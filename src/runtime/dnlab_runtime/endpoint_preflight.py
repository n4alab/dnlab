"""Read-only data-port preflight and durable per-start allocation evidence.

The original observation survives retries. Atomic veth MACs qualify the narrow
crash gap before recording kernel indices; labels alone never qualify a pair.
"""
import json

from .manifest import Conflict,canonical,fingerprint


class EndpointConflict(Conflict):
    pass


CONTRACT='read-only data endpoint preflight; durable allocation evidence before create'


def identity(link):
    return {key:link.get(key) for key in ('ifindex','link_index','address')}


def stored(journal,request):
    with journal.lock:
        row=journal.db.execute('SELECT p.payload FROM endpoint_preflights p JOIN operations o ON o.id=p.operation_id WHERE o.lab=? AND o.request_id=?',
            (request['lab_id'],request['request_id'])).fetchone()
    return json.loads(row[0]) if row else None


def observe(backend,request,spec):
    if not spec.get('endpoints'):return None
    journal=backend.management_journal
    scope=backend.linux.network_identity()
    container=backend.inspect(request,spec)
    proof={'journal_id':journal.identity,'request_fingerprint':fingerprint(request),
           'scope':scope,'endpoints':{},'workload_id':container['Id'] if container else None}
    birth=None
    if container:
        from .workload_generation import latest
        birth=latest(journal,request)
    def inspect(namespace=None):
        for endpoint in spec['endpoints']:
            host_name=endpoint['host_interface'];stage_name=backend.staging_name(endpoint)
            # Both permanent and temporary host names belong to the allocation.
            with journal.lock:
                for name in (host_name,stage_name):
                    row=journal.db.execute('SELECT lab,node FROM resources WHERE key=?',('interface:'+name,)).fetchone()
                    if row and tuple(row)!=(request['lab_id'],request['node_id']):
                        raise EndpointConflict('data endpoint name is reserved by another node')
            host=backend.linux.link(host_name);stage=backend.linux.link(stage_name)
            guest=backend.linux.link(endpoint['node_interface'],namespace) if namespace is not None else None
            moved=backend.linux.link(stage_name,namespace) if namespace is not None else None
            peers=[(place,value) for place,value in (('host',stage),('guest',guest),('moved',moved)) if value]
            if host is None:
                if peers:raise EndpointConflict('data endpoint peer name is occupied without its host pair')
                proof['endpoints'][host_name]=None
                continue
            if not container or namespace is None or not birth:
                raise EndpointConflict('data endpoint host name is occupied without a qualified workload')
            if len(peers)!=1:raise EndpointConflict('data endpoint peer identity is ambiguous or missing')
            place,peer=peers[0];host_mac,peer_mac=backend.endpoint_macs(request,spec,endpoint)
            alias=backend.alias(request,spec)
            if (host.get('address')!=host_mac or peer.get('address')!=peer_mac
                    or host.get('link_index')!=peer.get('ifindex') or peer.get('link_index')!=host.get('ifindex')
                    or host.get('linkinfo',{}).get('info_kind')!='veth' or peer.get('linkinfo',{}).get('info_kind')!='veth'
                    or host.get('ifalias') not in (None,'',alias)
                    or not host.get('ifalias') and place!='host'):
                raise EndpointConflict('data endpoint ownership or kernel pair differs')
            proof['endpoints'][host_name]={'host':identity(host),'peer':identity(peer),
                'creator':birth['creator'],'workload_id':container['Id'],
                'guest_namespace':backend.linux.namespace_identity(namespace) if place!='host' else None}
            with journal.lock:
                row=journal.db.execute('SELECT payload FROM endpoint_preflights WHERE operation_id=?',(birth['creator'],)).fetchone()
            if row is None:raise EndpointConflict('data endpoint birth proof is missing; adoption refused')
            creation=json.loads(row[0])
            if creation['original']['scope']!=scope:raise EndpointConflict('data endpoint birth namespace changed')
            pinned=creation['identities'].get(host_name)
            current=proof['endpoints'][host_name]
            if pinned and (any(current[key]!=pinned[key] for key in ('host','peer','creator','workload_id'))
                    or pinned.get('guest_namespace') and current['guest_namespace']!=pinned['guest_namespace']):
                raise EndpointConflict('data endpoint original birth identity changed')
    if container and container['State']['Running']:
        with backend.namespace(request,spec,container) as namespace:
            inspect(namespace)
    else:inspect()
    if backend.linux.network_identity()!=scope:raise EndpointConflict('data endpoint host namespace changed')
    prior=stored(journal,request)
    if prior:
        if (prior['original']['journal_id']!=journal.identity or prior['original']['request_fingerprint']!=fingerprint(request)
                or prior['original']['scope']!=scope):
            raise EndpointConflict('data endpoint original preflight context changed')
        for name,current in proof['endpoints'].items():
            pinned=prior['identities'].get(name)
            if pinned:
                if (current is None or any(current[key]!=pinned[key] for key in ('host','peer','creator','workload_id'))
                        or pinned.get('guest_namespace') and current['guest_namespace']!=pinned['guest_namespace']):
                    raise EndpointConflict('data endpoint original kernel identity changed')
            elif current is not None:
                with journal.lock:
                    op=journal.db.execute('SELECT id FROM operations WHERE lab=? AND request_id=?',(request['lab_id'],request['request_id'])).fetchone()
                if not op or current['creator']!=op[0]:
                    raise EndpointConflict('data endpoint appeared outside the original allocation')
    return proof


def checkpoint(backend,request,spec,operation_id):
    # Standalone backend helpers can construct explicit legacy test fixtures;
    # every Engine binds its journal before any runtime operation is exposed.
    if getattr(backend,'management_journal',None) is None:return
    proof=observe(backend,request,spec)
    if proof is None:return
    journal=backend.management_journal
    with journal.transaction():
        operation=journal.get(operation_id,private=True)
        if (operation['payload']!=request or operation['phase'] not in ('applying','verifying')
                or request['action']!='start'):
            raise EndpointConflict('data endpoint allocation lacks its original active start')
        prior=stored(journal,request)
        value=prior or {'original':proof,'identities':{}}
        for name,current in proof['endpoints'].items():
            if current is not None:value['identities'][name]=current
        journal.db.execute('INSERT INTO endpoint_preflights VALUES(?,?) ON CONFLICT(operation_id) DO UPDATE SET payload=excluded.payload',
            (operation_id,canonical(value)))
