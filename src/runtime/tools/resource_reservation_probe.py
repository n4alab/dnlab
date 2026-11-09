"""Image-backed read-only reservation checks while execution is held."""
from copy import deepcopy

from dnlab_runtime.execution import execution_gate
from dnlab_runtime.manifest import RuntimeErrorBase
from smoke import operation


def probe(*,client,docker,state,lab,image,management_network,register,report):
    results=[]
    for resource in ('container','published-port'):
        node='reservation-'+resource
        spec={'kind':'linux','image':image,'container_name':'drsp-'+lab+'-'+resource,
              'command':['python3','-c','import time; time.sleep(3600)']}
        if resource=='published-port':
            spec.update(management={'network':management_network,'ipv4':'198.19.229.10'},
                ports=[{'host_ip':'127.0.0.1','host_port':18080,'container_port':80,'protocol':'tcp'}])
        first={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'first-'+resource,
               'action':'start','expected_revision':0,'spec':spec}
        second=deepcopy(first);second.update(node_id=node+'-other',request_id='second-'+resource)
        if resource=='published-port':
            second['spec']['container_name']+='-other';second['spec']['management']['ipv4']='198.19.229.11'
        for request in (first,second):register(request['node_id'],request['spec'])
        accepted=None
        with execution_gate(state):
            try:
                for request in (first,second):
                    plan=client.request('POST','/v1/plan',request)
                    if 'management_preflight' in plan:request['management_preflight']=plan['management_preflight']
                accepted=client.request('POST','/v1/operations',first)
                assert client.request('GET','/v1/operations/'+accepted['id'])['phase']=='queued'
                for path in ('/v1/plan','/v1/operations'):
                    try:client.request('POST',path,second)
                    except RuntimeErrorBase as error:assert 'resource reserved' in str(error)
                    else:raise AssertionError('reserved resource accepted by '+path)
                assert all(docker.inspect(r['spec']['container_name']) is None for r in (first,second))
            finally:
                if accepted:
                    cancelled=client.request('POST','/v1/cancel-requests',first)
                    assert cancelled['id']==accepted['id'] and cancelled['cancel_requested']
        receipt=operation(client,accepted['id'],'cancelled')
        assert all(docker.inspect(r['spec']['container_name']) is None for r in (first,second))
        assert client.request('POST','/v1/plan',second)['mutations_performed'] is False
        results.append({'resource':resource,'plan_rejected':True,'submit_rejected':True,
                        'workload_never_allocated':True,'owner_cancelled':receipt['phase'],
                        'released_resource_available':True})
    report['reservation_preflight']=results
