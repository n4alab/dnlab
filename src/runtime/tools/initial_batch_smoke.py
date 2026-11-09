#!/usr/bin/env python3
"""Opt-in initial Linux batch gate over key-only SSH to two local runtimes."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_runtime.backend import Docker
from dnlab_runtime.transport import Client
from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.runtime_operations import OperationStore
from link_api_smoke import docker,cleanup_worker
from ssh_loopback_fixture import LoopbackSSH
from smoke import wait_for


def run(runtime_image,workload_image):
    root=Path(tempfile.mkdtemp(prefix='dnlab-initial-batch-'));root.chmod(0o700)
    lab='batch-'+uuid.uuid4().hex[:8];api=Docker();workers=[];transports={};targets={};clients={};store=None
    report={'status':'running','scope':'two-local-runtime-namespaces-over-key-only-SSH',
            'runtime_image':runtime_image,'workload_image':workload_image,'cross_host_qualified':False,
            'nos_qualified':False,'production_deploy_enabled':False,'checks':[]}
    batches=[];completed_cleanup=False
    code="import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print('READY',flush=True); time.sleep(3600)"
    try:
        for host in ('master','worker'):
            directory=root/host;directory.mkdir(mode=0o700)
            socket=str(directory/'runtime.sock');name='drsp-'+lab+'-'+host
            cid=docker('create','--name',name,'--label','io.dnlab.spike='+lab,'--privileged',
                '--network','none','--pid','host','--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                '--mount',f'type=bind,src={root},dst={root}',
                '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={directory}/boot-id,readonly',
                '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={directory}/boot-id',runtime_image,
                '--socket',socket,'serve','--state-dir',str(directory/'state'))
            worker={'id':cid,'name':name};workers.append(worker);api.start(cid)
            wait_for(lambda:Client(socket).request('GET','/v1/capabilities'))
            def guard(worker=worker):
                value=api.inspect(worker['id'])
                if (not value or value['Name']!='/'+worker['name'] or value['Image']!=runtime_image
                        or value['Config']['Labels'].get('io.dnlab.spike')!=lab or not value['State']['Running']):
                    raise RuntimeError('fixture daemon identity changed')
            ssh=LoopbackSSH(directory,['docker','exec','-i',name,'dnlab-runtime','--socket',socket],guard)
            transports[host]=ssh;targets[host]={'host':host,'socket_path':socket,'container_name':name}
            clients[host]=RuntimeClient(ssh,socket_path=socket,container_name=name)
        store=OperationStore(root/'coordinator')
        batch=RuntimeInitialDeployment(store,lambda target:clients[target['host']])
        def members(key):
            return [{'target':targets[host],'request':{'schema_version':1,'lab_id':lab,'node_id':key+'-'+host,
                'request_id':key+'-'+host,'expected_revision':0,'action':'start',
                'spec':{'kind':'linux','container_name':'drsp-'+lab+'-'+key+'-'+host,'image':workload_image,
                        'command':['python3','-c',code],'stop_timeout':10}}} for host in targets]
        def drive(key,terminal):
            deadline=time.monotonic()+150
            while time.monotonic()<deadline:
                value=batch.advance(lab,key)
                if value['phase']==terminal:return value
                time.sleep(.1)
            raise RuntimeError('finite batch wait exceeded')
        def ready(key):
            for value in batch.members(lab,key):
                binding=batch.binding(value)
                wait_for(lambda:'READY' in docker('logs',binding['container_id']))
        invalid=members('invalid');invalid[-1]['request']['spec']['image']='unpinned-image'
        try:batch.prepare(lab,'invalid',invalid)
        except Exception:pass
        else:raise AssertionError('invalid last member accepted')
        assert store.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
        report['checks'].append('invalid-last-member-no-child-intents-or-allocation')
        batch.prepare(lab,'cancel-before',members('cancel-before'));batches.append('cancel-before')
        batch.cancel(lab,'cancel-before');drive('cancel-before','cancelled')
        assert all(api.inspect(m['request']['spec']['container_name']) is None for m in members('cancel-before'))
        report['checks'].append('prepared-batch-cancelled-without-spawn')
        batch.prepare(lab,'deploy',members('deploy'));batches.append('deploy')
        assert len(batch.members(lab,'deploy'))==2
        assert all(api.inspect(m['request']['spec']['container_name']) is None for m in members('deploy'))
        report['checks'].append('all-intents-durable-before-first-submit')
        transports['master'].drop_next_submit_ack=True
        try:batch.advance(lab,'deploy')
        except Exception:pass
        else:raise AssertionError('lost ACK not observed')
        assert batch.get(lab,'deploy')['phase']=='recovery_required'
        original_name=members('deploy')[0]['request']['spec']['container_name']
        original=wait_for(lambda:api.inspect(original_name))['Id']
        store.close();store=OperationStore(root/'coordinator')
        batch=RuntimeInitialDeployment(store,lambda target:clients[target['host']])
        batch.recover(lab,'deploy');drive('deploy','completed');ready('deploy')
        bindings=batch.bindings(lab,'deploy')
        assert bindings['deploy-master']['container_id']==original
        starts=sum(e.get('argv',[])[-1:] == ['submit'] for ssh in transports.values() for e in ssh.events)
        assert starts==2
        report['checks'].append('lost-submit-ACK-reopen-recovery-same-generations-two-submits')
        batch.cancel(lab,'deploy');drive('deploy','cancelled')
        assert all(api.inspect(m['request']['spec']['container_name']) is None for m in members('deploy'))
        assert batch.cancel(lab,'deploy')['phase']=='cancelled'
        report['checks'].append('ordinary-tracked-shutdown-both-generations-and-terminal-cancel-replay')
        report['batches']={key:batch.get(lab,key) for key in batches}
        completed_cleanup=True;report['status']='passed'
    except Exception as error:
        report['status']='failed';report['error_type']=type(error).__name__;report['error']=str(error)
        raise
    finally:
        cleanup_errors=[]
        # Keep dependent daemons/state on uncertainty; no generic workload removal.
        if store is not None:
            for key in batches:
                try:
                    if batch.get(lab,key)['phase']!='cancelled':
                        batch.cancel(lab,key)
                        if batch.get(lab,key)['phase']=='recovery_required':batch.recover(lab,key)
                        drive(key,'cancelled')
                except Exception as error:cleanup_errors.append(type(error).__name__)
            store.close()
        for ssh in transports.values():
            try:ssh.close()
            except Exception as error:cleanup_errors.append(type(error).__name__)
        if not cleanup_errors:
            for worker in reversed(workers):
                try:cleanup_worker(api,worker,runtime_image,lab)
                except Exception as error:cleanup_errors.append(type(error).__name__)
        report['cleanup']={'verified':not cleanup_errors,'errors':cleanup_errors,
                           'owned_daemons_absent':all(api.inspect(w['id']) is None for w in workers)}
        if cleanup_errors:report['status']='failed'
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(root/'report.json',flush=True)
    assert report['cleanup']['verified'] and completed_cleanup
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--runtime-image',required=True);parser.add_argument('--workload-image',required=True)
    args=parser.parse_args();run(args.runtime_image,args.workload_image)
