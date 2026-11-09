"""Explicit bridge extension of the local link request, with two node owners."""
import json

from .manifest import RuntimeErrorBase,canonical,identifier


def validate(raw):
    allowed={'schema_version','kind','request_id','lab_id','link_id','action','endpoints','spec','lab_generation'}
    if set(raw)-allowed or type(raw.get('schema_version')) is not int or raw['schema_version']!=1:
        raise RuntimeErrorBase('unsupported bridge request schema or fields')
    for key in ('request_id','lab_id','link_id'):identifier(raw.get(key),key)
    if raw.get('action') not in ('create','delete','recover'):
        raise RuntimeErrorBase('unsupported link action')
    endpoints=raw.get('endpoints')
    if not isinstance(endpoints,list) or len(endpoints)!=2:
        raise RuntimeErrorBase('bridge requires two committed node endpoints')
    revisions={};names=set()
    for endpoint in endpoints:
        if not isinstance(endpoint,dict) or set(endpoint)!={'node_id','host_interface','expected_node_revision'}:
            raise RuntimeErrorBase('complete bridge endpoint owner required')
        for key in ('node_id','host_interface'):identifier(endpoint.get(key),key)
        if len(endpoint['host_interface'])>15 or endpoint['host_interface'] in names:
            raise RuntimeErrorBase('duplicate or invalid bridge interface')
        revision=endpoint['expected_node_revision'];node=endpoint['node_id']
        if type(revision) is not int or revision<1 or node in revisions and revisions[node]!=revision:
            raise RuntimeErrorBase('consistent committed node revisions required')
        names.add(endpoint['host_interface']);revisions[node]=revision
    if raw['action']=='create':
        spec=raw.get('spec')
        if not isinstance(spec,dict) or set(spec)!={'mtu'} or type(spec['mtu']) is not int or not 576<=spec['mtu']<=9216:
            raise RuntimeErrorBase('valid bridge MTU required')
    elif 'spec' in raw:raise RuntimeErrorBase('delete/recover use the committed link specification')
    value=json.loads(canonical(raw));value['endpoints'].sort(key=lambda e:e['host_interface'])
    return value


def endpoints(request):
    if request.get('kind')=='bridge':return request['endpoints']
    return [{key:request[key] for key in ('node_id','host_interface','expected_node_revision')}]


def transport_spec(request):
    if request.get('kind')!='bridge':return request['spec']
    return {'kind':'bridge','mtu':request['spec']['mtu'],
            'endpoints':[{key:edge[key] for key in ('node_id','host_interface')} for edge in endpoints(request)]}
