"""Owned negative Docker-generation gate, invoked by the isolated API fixture."""
import copy

from dnlab_runtime.backend import LABEL
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.workload_generation import latest
from smoke import operation,wait_for


def probe(*,api,client,state,lab,image,report):
    results=[]
    for mode in ('stop','coordinated-stop'):
        node='generation-'+mode;name='drsp-'+lab+'-'+mode
        spec={'kind':'linux','image':image,'container_name':name,
              'command':['python3','-c','import time; time.sleep(3600)'],'endpoints':[]}
        request={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'start-'+node,
                 'action':'start','expected_revision':0,'spec':spec}
        owned=[]
        try:
            operation(client,client.request('POST','/v1/operations',request)['id'])
            original=api.inspect(name)
            labels=copy.deepcopy(original['Config']['Labels'])
            owned.append((original['Id'],labels))
            journal=Journal(state)
            try:proof=latest(journal,request)
            finally:journal.close()
            assert proof['container_id']==original['Id'] and proof['phase']=='running'
            # Model an external recreation without updating runtime state.
            api.signal(original['Id'],'SIGKILL')
            wait_for(lambda:not api.inspect(original['Id'])['State']['Running'])
            api.remove(original['Id'])
            created=api.create(name,{'Image':image,'Cmd':spec['command'],'Labels':labels,
                                     'StopSignal':'SIGTERM','HostConfig':{'NetworkMode':'none',
                                     'RestartPolicy':{'Name':'no'},'AutoRemove':False}})
            owned.append((created['Id'],labels));api.start(created['Id'])
            assert created['Id']!=original['Id']
            try:client.request('GET',f'/v1/nodes/{lab}/{node}')
            except RuntimeErrorBase as error:assert 'generation' in str(error)
            else:raise AssertionError('inspect adopted recreated workload')
            stop={k:v for k,v in request.items() if k!='spec'}
            stop.update(action='stop',request_id='stop-'+node,expected_revision=1)
            if mode=='coordinated-stop':stop['stop_mode']='coordinated'
            accepted=client.request('POST','/v1/operations',stop)
            receipt=operation(client,accepted['id'],'recovery_required')
            assert 'generation' in receipt['error']
            current=api.inspect(created['Id'])
            assert current['State']['Running'] and current['Config']['Labels']==labels
            journal=Journal(state)
            try:
                assert latest(journal,request)==proof
                assert journal.node(lab,node)['revision']==1
            finally:journal.close()
            results.append({'mode':mode,'original_id':original['Id'],'replacement_id':created['Id'],
                            'phase':receipt['phase'],'replacement_preserved':True,'proof_preserved':True})
        finally:
            for container_id,labels in reversed(owned):
                current=api.inspect(container_id)
                if current is None:continue
                assert (current['Id']==container_id and current['Name']=='/'+name
                        and current['Config']['Labels']==labels and current['Image']==image
                        and labels[LABEL+'.lab']==lab and labels[LABEL+'.node']==node)
                if current['State']['Running']:
                    api.signal(container_id,'SIGKILL')
                    wait_for(lambda:not api.inspect(container_id)['State']['Running'])
                api.remove(container_id)
                assert api.inspect(container_id) is None
    report['workload_generation_replacement_gate']=results
    report['checks'].append('inspect and both stop modes refuse recreated Docker generations')
