"""Read-only initial native workload compilation from existing placement.

Network/services/link phases remain coordinator-owned. GUI WebUI declarations
are access metadata, not an implicit request for Docker port publication.
"""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
import ipaddress
import re

from . import generator,runtime_links,warm_links
from .runtime_operations import RuntimeOperationError,digest
from .webui_bindings import runtime_binding
from dnlab_multinode.utils.naming import micro_vd_container_name


class NativeManifestError(RuntimeOperationError):pass


def identifier(value,field):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',value):
        raise NativeManifestError('invalid native '+field)
    return value


def edge_key(a,ia,b,ib):return tuple(sorted(((a,ia),(b,ib))))


def compile_initial(topo,plan,*,batch_id,targets,resolved_images=None,node_options=None,
                    webui_allocations=None,revisions=None,lab_generation=1,management_plan=None,management_services=None):
    """Compile all Linux members without SSH, image resolution or mutation.

    ``resolved_images`` entries bind an original image reference to an already
    resolved immutable image. ``node_options`` accepts explicit native command
    arrays and stop timeouts; unqualified Containerlab attributes are refused.
    Each target explicitly selects the host runtime with ``container_name=None``
    or a named runtime container. Missing/invalid names never imply host fallback.
    """
    topo,plan,targets=deepcopy(topo),deepcopy(plan),deepcopy(targets)
    identifier(topo.name,'lab');identifier(batch_id,'batch')
    if plan.lab_name!=topo.name:raise NativeManifestError('schedule belongs to another lab')
    if type(lab_generation) is not int or lab_generation<1:raise NativeManifestError('invalid lab generation')
    resolved_images=deepcopy(resolved_images or {});node_options=deepcopy(node_options or {})
    revisions=deepcopy(revisions or {});allocations=deepcopy(webui_allocations or {})
    nodes=set(topo.nodes)
    if not nodes:raise NativeManifestError('initial deployment requires nodes')
    for mapping in (resolved_images,node_options,revisions,allocations):
        if not isinstance(mapping,dict) or set(mapping)-nodes:raise NativeManifestError('unknown node in compilation input')
    if set(topo.webui_wishlist)-nodes:raise NativeManifestError('unknown WebUI node')
    resolved_management = None
    if (topo.native_management or topo.management_networks or 'management_networks' in (topo.raw or {})
            or any(v.management_network != 'default' or v.management_port for v in topo.nodes.values())):
        from .management_segments import resolve
        from .config import ConfigError
        try:
            if management_plan is not None and topo.raw.get('dnlab_management_plan') is not None and management_plan != topo.raw['dnlab_management_plan']:
                raise ConfigError('management ledger differs from resolved topology plan')
            topo, resolved_management = resolve(topo, management_plan if management_plan is not None else (topo.raw or {}).get('dnlab_management_plan'))
        except ConfigError as error:
            raise NativeManifestError(str(error)) from error
    elif management_plan is not None or management_services is not None:
        raise NativeManifestError('management ledger requires an opt-in management topology')
    placement={}
    for host,assignment in plan.assignments.items():
        if host not in topo.all_hosts or assignment.host_name!=host:raise NativeManifestError('unknown or inconsistent scheduled host')
        for node in assignment.vd_names:
            if node not in nodes or node in placement:raise NativeManifestError('placement must contain every node exactly once')
            placement[node]=host
    if set(placement)!=nodes:raise NativeManifestError('placement is incomplete')
    hosts=set(placement.values())
    if not isinstance(targets,dict) or set(targets)!=hosts:raise NativeManifestError('complete assigned runtime targets required')
    for host,target in targets.items():
        if (not isinstance(target,dict) or set(target)!={'host','socket_path','container_name'} or target['host']!=host
                or not isinstance(target['socket_path'],str) or not target['socket_path'].startswith('/')):
            raise NativeManifestError('runtime target differs from assigned host')
        if target['container_name'] is not None:
            identifier(target['container_name'],'runtime container')
    desired=Counter(edge_key(l.source,l.source_iface,l.target,l.target_iface) for l in topo.links)
    scheduled=Counter()
    for link in plan.local_links:
        if (link.source not in nodes or link.target not in nodes or placement[link.source]!=placement[link.target]):
            raise NativeManifestError('local link does not match placement')
        scheduled[edge_key(link.source,link.source_iface,link.target,link.target_iface)]+=1
    for link in plan.cross_host_links:
        if (link.source_node not in nodes or link.target_node not in nodes
                or placement[link.source_node]!=link.source_host or placement[link.target_node]!=link.target_host
                or link.source_host==link.target_host):raise NativeManifestError('cross-host link does not match placement')
        scheduled[edge_key(link.source_node,link.source_iface,link.target_node,link.target_iface)]+=1
    if desired!=scheduled:raise NativeManifestError('schedule link footprint differs from topology')
    for link in topo.real_net_links:
        if link.node not in nodes or link.real_net not in topo.real_nets or link.host!=placement[link.node]:
            raise NativeManifestError('RealNet data attachment does not match placement')
    endpoints={node:[] for node in nodes};used=set();host_names=set()
    links=runtime_links.build_runtime_links(topo,plan)
    for link in links:
        for side in ('a','b'):
            edge=getattr(link,'endpoint_'+side)
            if 'node' not in edge:continue  # RealNet infrastructure is data only.
            node,iface=edge['node'],edge['iface'];host=getattr(link,'host_'+side);name=getattr(link,'host_endpoint_'+side)
            if host!=placement[node]:raise NativeManifestError('runtime link host differs from placement')
            if (node,iface) in used:raise NativeManifestError('data port has multiple owners')
            if iface in ('eth0','lo',topo.nodes[node].management_port) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}',iface):
                raise NativeManifestError('native data port is invalid or reserved for management')
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}',name) or (host,name) in host_names:
                raise NativeManifestError('native host endpoint is invalid or duplicated')
            used.add((node,iface));host_names.add((host,name))
            endpoints[node].append({'host_interface':name,'node_interface':iface})
    members=[]
    for name in sorted(nodes):
        vd=topo.nodes[name];identifier(name,'node')
        if vd.name!=name or vd.kind!='linux':raise NativeManifestError('only explicit native Linux nodes are qualified')
        if (topo.node_overrides or {}).get(name) or (topo.node_features or {}).get(name):
            raise NativeManifestError('native node assets/features are not qualified')
        if warm_links.capacity_for_node(topo,name):raise NativeManifestError('native warm-port adapter is not qualified')
        if resolved_management is not None and vd.management_port != 'eth0':
            raise NativeManifestError('native selected management port requires adapter qualification')
        selected = topo.management_networks[vd.management_network] if resolved_management is not None else topo.mgmt
        default = topo.mgmt
        try:
            topo.mgmt = selected
            generated=generator._build_node_dict(topo,name)
        finally:
            topo.mgmt = default
        # No guessing shell/entrypoint/binds/privilege/NOS defaults or accepting
        # nonfunctional native publication merely to satisfy a start request.
        if generated.get('ports'):raise NativeManifestError('explicit native port publication on dnlab-vrf is not qualified')
        if set(generated)-{'kind','image','mgmt-ipv4','mgmt-ipv6','env','ports'}:
            raise NativeManifestError('native topology attributes require an adapter qualification: '+name)
        image=vd.image
        if name in resolved_images:
            resolution=resolved_images[name]
            if not isinstance(resolution,dict) or set(resolution)!={'source','image'} or resolution['source']!=vd.image:
                raise NativeManifestError('resolved image source differs from topology')
            if re.fullmatch(r'(?:[^\s@]+@)?sha256:[0-9a-f]{64}',vd.image) and resolution['image']!=vd.image:
                raise NativeManifestError('pinned topology image cannot be replaced')
            image=resolution['image']
        if not isinstance(image,str) or not re.fullmatch(r'(?:[^\s@]+@)?sha256:[0-9a-f]{64}',image):
            raise NativeManifestError('image requires an explicit immutable resolution: '+name)
        env=generated.get('env',{})
        if not isinstance(env,dict) or any(not isinstance(k,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',k) or not isinstance(v,str) for k,v in env.items()):
            raise NativeManifestError('native environment requires explicit string values')
        management={'network':identifier(selected.network,'management network')}
        if not vd.mgmt_ipv4 or not vd.mgmt_mac:raise NativeManifestError('resolved management IPv4 and stable MAC required')
        for field,family in (('mgmt_ipv4',4),('mgmt_ipv6',6)):
            value=getattr(vd,field)
            if not value:continue
            try:address=ipaddress.ip_address(value)
            except ValueError:raise NativeManifestError('invalid resolved management address') from None
            if address.version!=family:raise NativeManifestError('management address family differs')
            management['ipv'+str(family)]=value
        mac=vd.mgmt_mac
        if not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}',mac) or int(mac[:2],16)&1 or mac=='00:00:00:00:00:00':
            raise NativeManifestError('invalid resolved management MAC')
        management['mac']=mac
        spec={'kind':'linux','image':image,'container_name':identifier(micro_vd_container_name(topo.name,name),'VD container'),
              'management':management,'env':deepcopy(env),'endpoints':sorted(endpoints[name],key=lambda e:e['node_interface'])}
        options=node_options.get(name,{})
        if not isinstance(options,dict) or set(options)-{'command','stop_timeout'}:raise NativeManifestError('unqualified native execution options')
        if 'command' in options and (not isinstance(options['command'],list) or not options['command'] or any(not isinstance(v,str) for v in options['command'])):
            raise NativeManifestError('native command must be an explicit nonempty string array')
        if 'stop_timeout' in options and (type(options['stop_timeout']) is not int or not 1<=options['stop_timeout']<=900):
            raise NativeManifestError('invalid native stop timeout')
        spec.update(deepcopy(options))
        revision=revisions.get(name,0)
        if type(revision) is not int or revision<0:raise NativeManifestError('invalid initial node revision')
        request={'schema_version':1,'lab_id':topo.name,'node_id':name,'lab_generation':lab_generation,
                 'request_id':'initial-'+digest({'batch':batch_id,'node':name})[:40],
                 'action':'start','expected_revision':revision,'spec':spec}
        members.append({'request':request,'target':deepcopy(targets[placement[name]])})
    for entries in allocations.values():
        if not isinstance(entries,list):raise NativeManifestError('invalid WebUI allocations')
        for entry in entries:runtime_binding(entry)  # Preserve validated metadata, no implicit publish.
    image_resolutions={m['request']['node_id']:{'source':topo.nodes[m['request']['node_id']].image,'image':m['request']['spec']['image']} for m in members}
    source={'members':members,'links':[asdict(link) for link in links],'image_resolutions':image_resolutions,
            'webui_wishlist':deepcopy(topo.webui_wishlist),'webui_allocations':allocations}
    if resolved_management is not None:
        from .management_services import compile_services
        source['management_plan'] = resolved_management
        external = topo.jumphost_net
        try:
            source['management_services'] = compile_services(resolved_management, {
                'network':external.network, 'bridge':external.bridge,
                'subnet':external.ipv4_subnet, 'gateway':external.ipv4_gw}, previous=management_services)
        except ConfigError as error:
            raise NativeManifestError(str(error)) from error
    return {**source,'fingerprint':digest(source)}
