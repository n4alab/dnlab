"""Image-only fault workers for the isolated local link API fixture."""
import json
from pathlib import Path

# Import only the image-installed runtime. The host mounts config/state, not code.
WORKER = r'''
import json,os,signal,sys
from pathlib import Path
from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
config=json.loads(Path(sys.argv[1]).read_text())
if not config['request']['lab_id'].startswith(('link-api-','bridge-api-')):
    raise RuntimeError('dedicated link API fixture required')
journal=Journal(Path(config['state']))
try:
    engine=Engine(journal,Backend())
    manager=engine.links.bridge_manager if config['request'].get('kind')=='bridge' else engine.links.manager
    if config['mode']=='cancel':
        result=engine.links.cancel(config['operation_id'])
        print(json.dumps(result),flush=True)
    else:
        operation=engine.links.submit(config['request'])
        print(json.dumps({'operation_id':operation['id']}),flush=True)
        if config['mode']=='retry':
            def crash(*args):os.kill(os.getpid(),signal.SIGKILL)
            manager.verify=crash
        else:
            original=manager.linux.run
            mutations=[0]
            def run(argv):
                result=original(argv)
                mutating=(argv[:2]==['ip','link'] and argv[2] in ('add','set','property','delete')
                          or argv[:2] in (['tc','filter'],['tc','qdisc']) and argv[2] in ('add','delete','del')
                          or argv[:2] in (['iptables','-I'],['iptables','-D']))
                if mutating:
                    mutations[0]+=1
                    if mutations[0]==config['mutation']:os.kill(os.getpid(),signal.SIGKILL)
                return result
            manager.linux.run=run
        engine.links.execute(operation['id'])
        raise RuntimeError('expected crash did not occur')
finally:
    journal.close()
'''


def probe(*, root, report, state, runtime_image, lab, link, daemon_start,
          daemon_stop, adapter, native_ping, link_action, peer_verify,
          command, docker, workers, network_mode='host'):
    records=report['replay_cancellation']=[]

    def worker(config,expected_exit):
        index=len(workers)
        path=root/f'replay-worker-{index}.json'
        path.write_text(json.dumps({**config,'state':str(state)},indent=2)+'\n')
        path.chmod(0o600)
        name=lab+'-replay-'+str(index)
        identity=docker('create','--name',name,'--label','io.dnlab.spike='+lab,
                        '--privileged','--network',network_mode,'--pid','host',
                        '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                        '--mount',f'type=bind,src={root},dst={root}',
                        '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
                        '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id',
                        '--entrypoint','python3',runtime_image,'-c',WORKER,str(path))
        workers.append({'id':identity,'name':name})
        result=command(['docker','start','-a',identity],check=False)
        observed=json.loads(docker('inspect',identity))[0]
        assert observed['State']['Running'] is False
        assert observed['State']['ExitCode']==expected_exit,(result.stdout,result.stderr,observed['State'])
        value=json.loads(docker('logs',identity))
        docker('rm',identity)
        return value

    # Each state is persisted by the actual image LinkEngine before SIGKILL.
    # Cancellation is a separate process after the crash, while the daemon is stopped.
    for mode,action,mutation,wanted in [('create','create',3,'cancelled'),
                                       ('delete','delete',1,'completed'),
                                       ('retry','create',0,'cancelled')]:
        if mode=='create':link_action('delete','before-crash-create')
        else:link_action('create','before-crash-'+mode)
        request={**link,'action':action,'request_id':'crash-'+mode}
        if action!='create':request.pop('spec')
        daemon_stop()
        accepted=worker({'request':request,'mode':mode,'mutation':mutation},137)
        cancelled=worker({'request':request,'mode':'cancel','operation_id':accepted['operation_id']},0)
        assert cancelled['cancel_requested'] is True and cancelled['phase']=='applying'
        daemon_start()
        # wait() deliberately raises on cancelled; poll through the CLI for evidence.
        import time
        deadline=time.monotonic()+15
        while True:
            result=adapter.invoke('link-status',accepted['operation_id'])
            if result['phase'] in ('completed','cancelled','failed','recovery_required'):break
            if time.monotonic()>=deadline:raise RuntimeError('replay worker did not settle')
            time.sleep(.05)
        assert result['phase']==wanted,result
        endpoints=link.get('endpoints') or [{'host_interface':link['host_interface']}]
        states=[adapter.invoke('link-inspect',lab,link['link_id'],edge['host_interface']) for edge in endpoints]
        state_value=states[0]
        assert all(value['committed_state']==state_value['committed_state'] and value['runtime_phase']==state_value['runtime_phase'] for value in states)
        if mode=='retry':
            assert state_value['committed_state']=='active' and state_value['kernel_state']=='present'
            traffic=native_ping()
        else:
            assert state_value['committed_state']=='deleted' and state_value['runtime_phase']=='cleaned'
            assert state_value['kernel_state']=='absent'
            traffic=native_ping(expected=False)
        peer_verify()
        records.append({'mode':mode,'worker_exit':137,'operation_id':accepted['operation_id'],
                        'phase':result['phase'],'inspection':state_value,'all_endpoint_inspections':states,'traffic':traffic})
    report['checks'].append('real image SIGKILL then persisted cancellation: create cleanup, delete completion, active retry preservation')
