"""Image-backed initial data endpoint conflicts in the fixture anchor namespace."""
from dnlab_runtime.backend import Backend
from dnlab_runtime.kernel_endpoint import signature
from dnlab_runtime.manifest import RuntimeErrorBase
from smoke import operation


def probe(*,api,client,state,lab,image,linux,report,native_ping,extra_workloads):
    results=[]
    for index,occupied in enumerate(('host','staging')):
        token=lab.rsplit('-',1)[-1]
        endpoint={'host_interface':'drsp'+token+'p'+str(index),'node_interface':'eth1'}
        name='drsp-'+lab+'-preflight-'+occupied
        node='preflight-'+occupied
        extra_workloads.append(({'lab_id':lab,'node_id':node},name))
        request={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'initial-'+node,
                 'action':'start','expected_revision':0,'spec':{'kind':'linux','image':image,
                 'container_name':name,'command':['python3','-c','import time; time.sleep(3600)'],
                 'endpoints':[endpoint]}}
        host=endpoint['host_interface'] if occupied=='host' else Backend.staging_name(endpoint)
        peer='drpf'+token+str(index)
        assert linux.link(host) is None and linux.link(peer) is None
        owned=None
        try:
            linux.command(['link','add',host,'type','veth','peer','name',peer])
            linux.command(['link','set',host,'alias','fixture-foreign:'+lab+':'+occupied])
            owned=linux.link(host);before=signature(owned);other=signature(linux.link(peer))
            try:client.request('POST','/v1/plan',request)
            except RuntimeErrorBase as error:assert 'data endpoint' in str(error)
            else:raise AssertionError('initial plan accepted a foreign data endpoint')
            accepted=client.request('POST','/v1/operations',request)
            result=operation(client,accepted['id'],'recovery_required')
            assert 'data endpoint' in result['error'] and api.inspect(name) is None
            # Read SQLite without initialization or any mutation from this process.
            import sqlite3
            db=sqlite3.connect(state.joinpath('journal.sqlite3').as_uri()+'?mode=ro',uri=True)
            try:
                assert db.execute('SELECT count(*) FROM workload_generations WHERE lab=? AND node=?',(lab,node)).fetchone()[0]==0
                assert db.execute('SELECT count(*) FROM endpoint_preflights WHERE operation_id=?',(accepted['id'],)).fetchone()[0]==0
            finally:db.close()
            assert signature(linux.link(host))==before and signature(linux.link(peer))==other
            native_ping()
            results.append({'occupied':occupied,'plan_rejected':True,'apply_phase':result['phase'],
                            'workload_never_allocated':True,'foreign_pair_preserved':True,'control_traffic_preserved':True})
        finally:
            if owned:
                assert signature(linux.link(host))==signature(owned)
                linux.delete_link(owned)
                assert linux.link(host) is None and linux.link(peer) is None
    report['data_endpoint_preflight']=results
    report['checks'].append('foreign host/staging endpoints rejected before workload allocation; control traffic intact')
