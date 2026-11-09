"""Image-backed inspection of a qualified new birth before its node commit."""
import json

from dnlab_runtime.journal import Journal
from link_api_smoke import cleanup_worker,docker
from smoke import operation,wait_for


def probe(*,root,state,lab,daemon,anchor,api,client,adapter,image,runtime_image,
          service_start,service_stop,workers,report,extra_workloads):
    node='inspect-transition';name='drsp-'+lab+'-inspect'
    extra_workloads.append(({'lab_id':lab,'node_id':node},name))
    ready='INSPECT_READY'
    program="import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print('INSPECT_READY',flush=True); time.sleep(3600)"
    spec={'kind':'linux','image':image,'container_name':name,
          'command':['python3','-u','-c',program],'stop_timeout':5,'endpoints':[]}
    request={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'inspect-start',
             'action':'start','expected_revision':0,'spec':spec}
    operation(client,client.request('POST','/v1/operations',request)['id'])
    wait_for(lambda:ready in docker('logs',name))
    stop={k:v for k,v in request.items() if k!='spec'}
    stop.update(action='stop',request_id='inspect-stop',expected_revision=1)
    operation(client,client.request('POST','/v1/operations',stop)['id'])
    restart={**request,'request_id':'inspect-restart','expected_revision':2,
             'spec':{**spec,'command':['python3','-u','-c',program.replace('sleep(3600)','sleep(7200)')],
                     'env':{'TOKEN':'inspect-fixture-private-marker'}}}
    config=root/'inspect-restart.json';config.write_text(json.dumps(restart));config.chmod(0o600)

    def worker(suffix,code):
        worker_name=daemon['name']+'-'+suffix
        identity=docker('create','--name',worker_name,'--label','io.dnlab.spike='+lab,
            '--privileged','--workdir','/','--network','container:'+anchor['id'],'--pid','host',
            '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
            '--mount',f'type=bind,src={root},dst={root}',
            '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
            '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id','--entrypoint','python3',runtime_image,
            '-u','-c',code,str(state),str(config))
        value={'id':identity,'name':worker_name};workers.append(value);api.start(identity)
        return value

    service_stop()
    crash=worker('inspect-crash', '''import os,signal,json,sys
from pathlib import Path
from dnlab_runtime.journal import Journal
from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
j=Journal(Path(sys.argv[1]));e=Engine(j,Backend())
r=json.loads(Path(sys.argv[2]).read_text());o=j.submit(r)
def finish(*args,**kwargs):os.kill(os.getpid(),signal.SIGKILL)
j.finish=finish;e.execute(o['id'])
''')
    assert docker('wait',crash['id'])=='137'
    journal=Journal(state)
    try:pending=journal.find_request(lab,node,restart['request_id'])
    finally:journal.close()
    assert pending['phase']=='verifying'
    holder=None
    try:
        holder=worker('inspect-hold', '''import sys,time
from pathlib import Path
from dnlab_runtime.journal import Journal
j=Journal(Path(sys.argv[1]))
with j.execution_lock:
 print('HELD',flush=True);time.sleep(120)
''')
        wait_for(lambda:'HELD' in docker('logs',holder['id']))
        service_start()
        bound=adapter.bound_to(client.request('GET','/v1/capabilities')['journal_id'])
        view=bound.inspect_node(lab,node)
        assert view['revision']==2 and view['committed_state']=='stopped' and view['container_state']=='running'
        assert view['operation']['id']==pending['id'] and view['operation']['phase']=='verifying'
        assert view['workload']['phase']=='bound' and view['workload']['generation']==2
        assert view['workload']['spec_fingerprint']!=view['committed_spec_fingerprint']
        assert view['guest_readiness']=='unknown' and 'inspect-fixture-private-marker' not in json.dumps(view)
        assert api.inspect(holder['id'])['State']['Running']
        report['inspect_pending_restart']=view
    finally:
        if holder:cleanup_worker(api,holder,runtime_image,lab)
    operation(client,pending['id'])
    completed=bound.inspect_node(lab,node)
    assert completed['revision']==3 and completed['operation'] is None
    assert completed['workload']['phase']=='running' and completed['container_id']==view['container_id']
    wait_for(lambda:ready in docker('logs',name))
    stop.update(request_id='inspect-final-stop',expected_revision=3)
    operation(client,client.request('POST','/v1/operations',stop)['id'])
    final=bound.inspect_node(lab,node)
    assert final['revision']==4 and final['container_state']=='absent' and final['workload']['phase']=='cleaned'
    report['inspect_restart_replayed_same_generation']=True
    report['checks'].append('image SIGKILL before new-spec commit; bound inspect while execution gate held; same-generation replay')
