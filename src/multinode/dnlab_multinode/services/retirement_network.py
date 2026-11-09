"""Read-only retirement qualification; never admits or mutates an endpoint.

The ordinary NetworkGuard remains strict. This separate observer permits an
unmarked network only for an exact set of runtime-qualified original VD IDs.
"""
from copy import deepcopy
import re

if 'NetworkError' not in globals():
    from .management_network_host import NetworkError


def observe(guard, authorizations):
    with guard.worker.locked():
        record=guard.read();guard.worker.verify_ready(record)
        if set(authorizations)!=set(guard.networks):
            raise NetworkError('complete retirement network endpoint authorization required')
        result={}
        for segment,expected in sorted(guard.networks.items()):
            row=record.get('networks',{}).get(segment)
            if not row or row['expected']!=expected or row['phase']!='active' or type(row.get('used')) is not bool:
                raise NetworkError('retirement network original birth missing')
            # Validate original ID/name, nonce, config, plugin and IPAM with
            # the existing guard. The temporary admission view is never saved.
            actual=guard.observe({**deepcopy(row),'used':True})
            allowed=authorizations[segment]
            if not isinstance(allowed,dict) or any(not re.fullmatch('[0-9a-f]{64}',str(cid))
                    or not isinstance(p,dict) or set(p)!={'node','name','image','spec_fingerprint','creator','management','allow_absent'}
                    or type(p['allow_absent']) is not bool or not isinstance(p['management'],dict)
                    for cid,p in allowed.items()):
                raise NetworkError('original runtime retirement proof required')
            if (not set(actual['Containers'])<=set(allowed)
                    or any(not p.get('allow_absent') for cid,p in allowed.items() if cid not in actual['Containers'])):
                raise NetworkError('retirement network has unqualified endpoints')
            endpoint_ids=set();containers={}
            for cid in sorted(actual['Containers']):
                proof=allowed[cid]
                if (not re.fullmatch('[0-9a-f]{64}',cid) or set(proof)!=
                        {'node','name','image','spec_fingerprint','creator','management','allow_absent'}
                        or type(proof['allow_absent']) is not bool):
                    raise NetworkError('original runtime retirement proof required')
                container=guard.docker.call('GET','/containers/'+cid+'/json')
                labels=container.get('Config',{}).get('Labels') or {}
                if (container.get('Id')!=cid or container.get('Name')!='/'+proof['name']
                        or container.get('Image')!=proof['image']
                        or any(labels.get(k)!=v for k,v in {'org.dnlab.runtime':'v1',
                            'org.dnlab.runtime.lab':expected['lab'],'org.dnlab.runtime.node':proof['node'],
                            'org.dnlab.runtime.spec':proof['spec_fingerprint'],
                            'org.dnlab.runtime.creator':proof['creator']}.items())
                        or not re.fullmatch('[0-9a-f]{32}',str(labels.get('org.dnlab.runtime.birth','')))):
                    raise NetworkError('retirement Docker generation differs from runtime proof')
                endpoint=container.get('NetworkSettings',{}).get('Networks',{}).get(expected['network'],{})
                eid=endpoint.get('EndpointID');inventory=actual['Containers'][cid]
                if (endpoint.get('NetworkID')!=row['id'] or not re.fullmatch('[0-9a-f]{64}',str(eid))
                        or inventory.get('EndpointID')!=eid or inventory.get('Name')!=proof['name']):
                    raise NetworkError('retirement endpoint generation differs')
                for family,field,inventory_field in ((4,'IPAddress','IPv4Address'),(6,'GlobalIPv6Address','IPv6Address')):
                    wanted=proof['management'].get('ipv'+str(family),'')
                    if endpoint.get(field,'')!=wanted or (inventory.get(inventory_field,'').split('/')[0])!=wanted:
                        raise NetworkError('retirement endpoint address differs')
                if proof['management'].get('mac') and endpoint.get('MacAddress')!=proof['management']['mac']:
                    raise NetworkError('retirement endpoint MAC differs')
                endpoint_ids.add(eid);containers[cid]={'endpoint_id':eid,'birth':labels['org.dnlab.runtime.birth']}
            if len(endpoint_ids)!=len(containers):raise NetworkError('retirement endpoint IDs are ambiguous')
            plugin=guard.plugin()
            present={eid:v for eid,v in plugin['endpoints'].items() if v.get('network_id')==row['id']}
            if set(present)!=endpoint_ids:
                raise NetworkError('retirement plugin endpoint inventory differs')
            for cid,value in containers.items():
                endpoint=present[value['endpoint_id']];management=allowed[cid]['management']
                if any(endpoint.get('ipv'+str(f),'')!=management.get('ipv'+str(f),'') for f in (4,6)):
                    raise NetworkError('retirement plugin endpoint address differs')
                if management.get('mac') and endpoint.get('mac')!=management['mac']:
                    raise NetworkError('retirement plugin endpoint MAC differs')
            result[segment]={'id':row['id'],'nonce':row['nonce'],'expected':deepcopy(expected),
                             'used':row['used'],'containers':containers}
        return {'kernel':guard.worker.verify_ready(record),'networks':result}
