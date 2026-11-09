"""Durable local lab management network identity, independent of workload births.

Pins survive stop/compensation; a reopened lab uses its new explicit epoch.
Endpoint membership and runtime Docker counters are deliberately not identity.
"""
import json
import ipaddress

from .manifest import Conflict, canonical, fingerprint


class NetworkIdentityConflict(Conflict):
    pass


def snapshot(network):
    if (not isinstance(network, dict) or not isinstance(network.get('Id'), str)
            or not network['Id'] or not isinstance(network.get('Name'), str) or not network['Name']):
        raise NetworkIdentityConflict('management network identity is incomplete')
    fields=('Id','Name','Driver','Scope','Internal','Attachable','EnableIPv6','Ingress','ConfigOnly','ConfigFrom')
    result={key:network.get(key) for key in fields}
    for key in ('Options','Labels'):
        value=network.get(key)
        if value is not None and not isinstance(value,dict):
            raise NetworkIdentityConflict('management network configuration is malformed')
        result[key]=value or {}
    ipam=network.get('IPAM')
    if not isinstance(ipam,dict) or not isinstance(ipam.get('Config',[]),list):
        raise NetworkIdentityConflict('management network IPAM is malformed')
    if ipam.get('Options') is not None and not isinstance(ipam['Options'],dict):
        raise NetworkIdentityConflict('management network IPAM options are malformed')
    result['IPAM']={'Driver':ipam.get('Driver'),'Options':ipam.get('Options') or {},'Config':ipam.get('Config',[])}
    return json.loads(canonical(result))


def validate_configuration(network,management):
    entries=network.get('IPAM',{}).get('Config')
    if not isinstance(entries,list) or not entries:
        raise NetworkIdentityConflict('management network has no qualified IPAM pools')
    pools=[]
    for entry in entries:
        try:
            if not isinstance(entry,dict):raise ValueError()
            pool=ipaddress.ip_network(entry['Subnet'],strict=True)
            gateway=ipaddress.ip_address(entry['Gateway'])
            if gateway not in pool or gateway.version!=pool.version:raise ValueError()
        except (KeyError,TypeError,ValueError):
            raise NetworkIdentityConflict('management network subnet or gateway is invalid') from None
        if any(pool.version==other.version and pool.overlaps(other) for other,_ in pools):
            raise NetworkIdentityConflict('management network IPAM pools overlap')
        pools.append((pool,gateway))
    for field,family in (('ipv4',4),('ipv6',6)):
        if not management.get(field):continue
        address=ipaddress.ip_address(management[field])
        matches=[(pool,gateway) for pool,gateway in pools if pool.version==family and address in pool]
        if len(matches)!=1:raise NetworkIdentityConflict('management address is outside its qualified subnet')
        pool,gateway=matches[0]
        if address==gateway or family==4 and pool.prefixlen<31 and address in (pool.network_address,pool.broadcast_address):
            raise NetworkIdentityConflict('management address is reserved by the subnet')
        if family==6 and network.get('EnableIPv6') is not True:
            raise NetworkIdentityConflict('management IPv6 network is not enabled')
        if management.get('gateway') and str(gateway)!=management['gateway']:
            raise NetworkIdentityConflict('management assignment gateway differs from network IPAM')


def binding(journal,request,name):
    from .lab_closure import generation
    with journal.lock:
        rows=journal.db.execute('SELECT payload FROM management_network_proofs WHERE lab=? AND generation=? AND name=? ORDER BY rowid',
            (request['lab_id'],generation(journal,request['lab_id']),name)).fetchall()
    values=[json.loads(row[0]) for row in rows]
    if values and any(value['network']!=values[0]['network'] for value in values):
        raise NetworkIdentityConflict('management network proofs disagree within the lab')
    return values[0] if values else None


def selected(backend,request,spec):
    from .management_authority import assignment,effective
    journal=getattr(backend,'management_journal',None)
    authority=assignment(journal,request['lab_id'],request['node_id']) if journal else None
    # A tracked handoff validates both endpoints itself while disconnected.
    if authority and authority['phase']=='pending':return None
    return effective(journal,request,spec)


def detached_placeholder(backend,request,spec,container,management,network,*,retained_network_id=False):
    """Docker clears endpoint IDs before start and after namespace teardown.

    Only an original, journal-bound birth with exact pinned NetworkMode (or
    its tracked move assignment) can authorize that inactive placeholder.
    """
    journal=backend.management_journal
    state=container.get('State',{});settings=container.get('NetworkSettings',{})
    endpoints=settings.get('Networks',{})
    if (state.get('Running') is not False or state.get('Pid')!=0 or state.get('Status') not in ('created','exited')
            or settings.get('SandboxID') or set(endpoints)!={network['Name']}):return False
    endpoint=endpoints[network['Name']]
    allowed_ids=('',network['Id']) if retained_network_id else ('',)
    if endpoint.get('NetworkID','') not in allowed_ids or endpoint.get('EndpointID'):return False
    from .workload_generation import latest
    from .management_authority import assignment
    birth=latest(journal,request)
    if not birth or birth['container_id']!=container['Id'] or birth['spec']!=fingerprint(spec):return False
    authority=assignment(journal,request['lab_id'],request['node_id'])
    moved=authority and authority.get('container_id')==container['Id'] and authority.get('connection',{}).get('network_id')==network['Id']
    if container.get('HostConfig',{}).get('NetworkMode')!=network['Id'] and not moved:return False
    config=endpoint.get('IPAMConfig') or {}
    return all(config.get(key,'')==management.get(field,'') for key,field in (('IPv4Address','ipv4'),('IPv6Address','ipv6')))


def check(backend,request,spec,container=None,*,required=False):
    journal=getattr(backend,'management_journal',None)
    management=selected(backend,request,spec)
    if not management or journal is None:return None
    prior=binding(journal,request,management['network'])
    if not required and prior is None and container is None:return None
    network=backend.docker.network(management['network'])
    proof=snapshot(network)
    validate_configuration(network,management)
    if (network['Name']!=management['network'] or network.get('Driver')!='dnlab-vrf'
            or network.get('IPAM',{}).get('Driver')!='dnlab-vrf'
            or (network.get('Labels') or {}).get('io.dnlab.lab')!=request['lab_id']
            or (network.get('Labels') or {}).get('io.dnlab.managed')!='mgmt-vrf'):
        raise NetworkIdentityConflict('management network ownership differs')
    if prior and prior['network']!=proof:
        raise NetworkIdentityConflict('management network identity or configuration changed; recovery required')
    if management.get('network_id') and management['network_id']!=proof['Id']:
        raise NetworkIdentityConflict('management assignment network identity changed')
    if management.get('mac'):
        from .workload_generation import latest
        birth=latest(journal,request)
        owned_id=container['Id'] if container is not None else birth['container_id'] if birth else None
        for endpoint_id,endpoint in (network.get('Containers') or {}).items():
            if endpoint.get('MacAddress','').lower()==management['mac'] and endpoint_id!=owned_id:
                raise NetworkIdentityConflict('management MAC occupied by another endpoint')
    if container is not None:
        if prior is None and not management.get('network_id'):
            raise NetworkIdentityConflict('initial management network proof missing; implicit adoption refused')
        endpoints=container.get('NetworkSettings',{}).get('Networks',{})
        if (set(endpoints)!={network['Name']} or endpoints[network['Name']].get('NetworkID')!=proof['Id']) and not detached_placeholder(backend,request,spec,container,management,network):
            raise NetworkIdentityConflict('management Docker endpoint identity differs')
        if management.get('mac'):
            endpoint=endpoints.get(network['Name'],{})
            observed=endpoint.get('MacAddress','')
            if observed.lower()!=management['mac']:
                if observed or not detached_placeholder(backend,request,spec,container,management,network,retained_network_id=True):
                    raise NetworkIdentityConflict('native management endpoint MAC differs')
        if management.get('mac') and container['State']['Running']:
            verify_kernel_mac(backend,request,spec,container,network,management['mac'])
    return network


def verify_kernel_mac(backend,request,spec,container,network,mac):
    from .endpoint_uplink import vrf_host_peer
    endpoint=container['NetworkSettings']['Networks'][network['Name']]
    endpoint_id=endpoint.get('EndpointID')
    if not isinstance(endpoint_id,str) or len(endpoint_id)!=64:
        raise NetworkIdentityConflict('native management endpoint ID missing')
    peer_name=vrf_host_peer(network['Id'],endpoint_id)
    with backend.linux.namespace(container['State']['Pid']) as namespace:
        fresh=backend.docker.inspect(container['Id'])
        if (not fresh or fresh['Id']!=container['Id'] or not fresh['State']['Running']
                or fresh['State']['Pid']!=container['State']['Pid']):
            raise NetworkIdentityConflict('native management namespace generation changed')
        backend.owned(request,spec,fresh)
        peer=backend.linux.link(peer_name)
        links=json.loads(backend.linux.command(['-j','-d','link','show'],namespace))
        matches=[link for link in links if peer and link.get('link_index')==peer.get('ifindex')
                 and peer.get('link_index')==link.get('ifindex') and link.get('linkinfo',{}).get('info_kind')=='veth']
        if (not peer or peer.get('linkinfo',{}).get('info_kind')!='veth'
                or peer.get('master')!=(network.get('Options') or {}).get('dnlab.bridge')
                or len(matches)!=1 or matches[0].get('address')!=mac):
            raise NetworkIdentityConflict('native management kernel endpoint MAC or peer differs')


def pin(backend,request,spec,operation_id):
    journal=getattr(backend,'management_journal',None)
    network=check(backend,request,spec,required=True)
    if not network or journal is None:return network
    from .lab_closure import generation
    from .management_authority import assignment
    with journal.transaction():
        operation=journal.get(operation_id,private=True)
        original=operation['payload']
        if (operation['lab']!=request['lab_id'] or operation['node']!=request['node_id']
                or original['action']!='start' or fingerprint(original['spec'])!=fingerprint(spec)
                or operation['phase'] in ('completed','cancelled','failed')):
            raise NetworkIdentityConflict('management pin lacks original active start intent')
        prior=binding(journal,request,network['Name'])
        proof=snapshot(network)
        if prior:
            if prior['network']!=proof:raise NetworkIdentityConflict('management pin changed before creation')
        else:
            current=journal.node(request['lab_id'],request['node_id'])
            epoch=generation(journal,request['lab_id'])
            if current and current['spec'].get('management') and not assignment(journal,request['lab_id'],request['node_id']):
                from .workload_generation import latest
                from .manifest import NotFound
                birth=latest(journal,request)
                try:previous=journal.get(birth['creator'],private=True) if birth else None
                except NotFound:previous=None
                if not previous or previous['payload'].get('lab_generation',1)==epoch:
                    raise NetworkIdentityConflict('committed management proof missing; implicit adoption refused')
            value={'network':proof,'operation_id':operation_id,'request_fingerprint':operation['hash']}
            journal.db.execute('INSERT INTO management_network_proofs VALUES(?,?,?,?,?)',
                (request['lab_id'],request['node_id'],epoch,network['Name'],canonical(value)))
    # Repeat after the durable write, before any Docker allocation.
    preflight(backend,request,spec,required=True)
    return check(backend,request,spec,required=True)


PREFLIGHT_CONTRACT='read-only management proof; request-bound apply and recovery before allocation'


def preflight(backend,request,spec,*,required=False):
    """Observe without pinning; the original request carries the observation."""
    network=check(backend,request,spec,required=True)
    proof=None
    if network:
        original={key:value for key,value in request.items() if key!='management_preflight'}
        proof={'journal_id':backend.management_journal.identity,
               'request_fingerprint':fingerprint(original),
               'management':selected(backend,request,spec),'network':snapshot(network)}
    expected=request.get('management_preflight')
    if expected is not None and fingerprint(expected)!=fingerprint(proof):
        raise NetworkIdentityConflict('management preflight changed; original observation required')
    if required and proof is not None and expected is None:
        raise NetworkIdentityConflict('management preflight is required before allocation')
    return proof
