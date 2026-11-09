#!/usr/bin/env python3
"""Opt-in local workload-fence gate; no management/service provisioning claim."""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_runtime.backend import Docker
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.runtime_operations import OperationStore,OperationDriver,RuntimeOperationError
from dnlab_multinode.services import management_barrier as barrier
from smoke import Service,wait_for,command


class Local:
    """Actual native CLI with bounded argv/stdin and injected lost replies."""
    def __init__(self):self.lose=None;self.events=[]
    def run(self,cmd):return self.run_input(cmd,None)
    def run_input(self,cmd,payload):
        argv=shlex.split(cmd)
        if argv[0]!='dnlab-runtime':raise RuntimeError('unexpected fixture command')
        result=subprocess.run([sys.executable,'-m','dnlab_runtime.cli',*argv[1:]],
            input=payload,text=True,capture_output=True,timeout=20,
            env={**os.environ,'PYTHONPATH':str(SOURCE)})
        action=next((a for a in argv if a.startswith('management-')),argv[-1])
        self.events.append({'action':action,'exit_code':result.returncode,'stderr':result.stderr})
        if result.returncode:raise RuntimeError('fixture CLI rejected '+action+': '+result.stderr.strip())
        if action==self.lose:self.lose=None;raise OSError('injected lost '+action+' reply')
        return result.stdout


def run(image):
    root=Path(tempfile.mkdtemp(prefix='dnlab-management-barrier-'));root.chmod(0o700)
    lab='fence-'+uuid.uuid4().hex[:10];name='drsp-'+lab+'-vd'
    services={};clients={};transports={};targets={};store=None;driver=None;operations=None;api=Docker();container_ids=[]
    report={'status':'running','scope':'two native runtime processes on one local host; one native VD and empty worker',
            'management_provisioning_qualified':False,'physical_multihost_qualified':False,'image':image,'checks':[]}
    def reopen_store():
        nonlocal store,driver,operations
        if store is not None:store.close()
        store=OperationStore(root/'coordinator')
        driver=barrier.Driver(store,lambda target:clients[target['host']])
        operations=OperationDriver(store,lambda target:clients[target['host']])
    def drive(request):
        operations.prepare(request,targets['master']['target'])
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            result=operations.advance(lab,request['request_id'])
            if result['phase']=='completed':return result
            if result['phase'] in ('failed','cancelled','recovery_required'):raise RuntimeError('fixture lifecycle '+result['phase'])
            time.sleep(.05)
        raise RuntimeError('fixture lifecycle deadline exceeded')
    def shutdown(revision,key):
        return {'schema_version':1,'lab_id':lab,'node_id':'vd','request_id':key,'expected_revision':revision,'action':'stop'}
    def crash_restart(host):
        service=services[host];process=service.process
        if process.poll() is not None:raise RuntimeError('fixture daemon already exited')
        # The process is our original Popen child, not a PID rediscovered by name.
        process.kill();process.wait(timeout=10);service.process=None
        service.log.close();service.log=None;service.start()
        if clients[host].qualify_node()['journal_id']!=targets[host]['journal_id']:
            raise RuntimeError('runtime journal changed after process crash')
    def denied(callback,explanation):
        try:callback()
        except (RuntimeError,OSError):return
        raise AssertionError(explanation)
    try:
        observed=json.loads(command(['docker','image','inspect',image]))[0]
        if observed['Id']!=image:raise RuntimeError('pinned fixture image required')
        for host in ('master','worker'):
            directory=root/host;directory.mkdir(mode=0o700)
            service=Service('native',directory,None,lab+'-'+host);services[host]=service;service.start()
            transport=Local();transports[host]=transport
            client=RuntimeClient(transport,socket_path=service.client.socket_path)
            journal=client.qualify_node(inspection=True)['journal_id'];clients[host]=client.bound_to(journal)
            targets[host]={'target':{'host':host,'socket_path':service.client.socket_path,'container_name':None},'journal_id':journal}
        reopen_store()
        code="import signal,sys,time;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));print('READY',flush=True);time.sleep(3600)"
        start={'schema_version':1,'lab_id':lab,'node_id':'vd','request_id':'start','expected_revision':0,'action':'start',
               'spec':{'kind':'linux','container_name':name,'image':image,'command':['python3','-c',code],'stop_timeout':10}}
        drive(start);cid=api.inspect(name)['Id'];container_ids.append(cid)
        wait_for(lambda:'READY' in command(['docker','logs',cid]))
        plan={'hosts':{h:{'purpose':'fence-only; no network or service mutation'} for h in targets}}
        denied(lambda:driver.prepare(lab,'running-denied',plan,targets),'running workload admitted offline')
        assert barrier.get(store,lab) is None
        assert clients['master'].inspect_node(lab,'vd')['container_id']==cid
        drive(shutdown(1,'stop'));assert api.inspect(cid) is None
        before=clients['master'].inspect_node(lab,'vd')
        report['checks'].append('running read-only rejection creates no coordinator fence; ordinary graceful stop remains possible')
        cancelled_intent=driver.prepare(lab,'cancel-acquisition',plan,targets)
        contexts={h:{k:cancelled_intent[k] for k in ('barrier_id','generation','plan_fingerprint')}|
                  {'workload_fingerprint':cancelled_intent['preflights'][h]['workload_fingerprint']} for h in targets}
        transports['worker'].lose='management-acquire'
        denied(lambda:driver.acquire(lab,'cancel-acquisition'),'lost acquisition reply not injected')
        assert barrier.get(store,lab)['phase']=='acquiring'
        assert set(barrier.get(store,lab)['receipts'])=={'master'}
        reopen_store()
        restart={**start,'request_id':'restart','expected_revision':2}
        denied(lambda:store.prepare(restart,targets['master']['target'],targets['master']['journal_id']),'coordinator start crossed acquisition')
        denied(lambda:clients['master'].submit_node(restart),'runtime start crossed acquisition')
        transports['worker'].lose='management-cancel'
        denied(lambda:driver.cancel(lab,'cancel-acquisition'),'lost cancellation reply not injected')
        assert barrier.get(store,lab)['phase']=='cancelling'
        services['worker'].stop()
        denied(lambda:driver.cancel(lab,'cancel-acquisition'),'unavailable worker accepted cancellation')
        assert barrier.get(store,lab)['phase']=='cancelling'
        denied(lambda:store.prepare(restart,targets['master']['target'],targets['master']['journal_id']),'coordinator start crossed incomplete cancellation')
        services['worker'].start();crash_restart('master');reopen_store()
        assert driver.cancel(lab,'cancel-acquisition')['phase']=='cancelled'
        for host in targets:
            denied(lambda host=host:clients[host].management_barrier(lab,'acquire',contexts[host]),'late acquisition accepted after tombstone')
        report['checks'].append('lost acquire and cancel replies; unavailable worker; coordinator/runtime restarts; complete cancellation and late-acquire rejection')
        driver.prepare(lab,'qualified-fence',plan,targets);driver.acquire(lab,'qualified-fence')
        crash_restart('master');assert driver.acquire(lab,'qualified-fence')['phase']=='held'
        transports['worker'].lose='management-activate'
        denied(lambda:driver.begin_provisioning(lab,'qualified-fence'),'lost activation reply not injected')
        assert barrier.get(store,lab)['phase']=='activating'
        denied(lambda:driver.cancel(lab,'qualified-fence'),'partial provisioning seal cancellable')
        assert driver.begin_provisioning(lab,'qualified-fence')['phase']=='provisioning'
        denied(lambda:driver.cancel(lab,'qualified-fence'),'sealed provisioning cancellable')
        def ready(plan,targets):
            hosts={}
            for host,entry in targets.items():
                caps=clients[host].qualify_node(inspection=True)
                assert caps['journal_id']==entry['journal_id']
                hosts[host]={'runtime_journal':caps['journal_id'],'scope':'fence-only; no management provisioning'}
            current=clients['master'].inspect_node(lab,'vd')
            assert current['committed_state']=='stopped' and current['container_state']=='absent'
            assert current['workload']==before['workload'] and current['revision']==before['revision']
            hosts['master']['stopped_inventory']=current
            return {'plan_fingerprint':barrier.digest(plan),'hosts':hosts}
        transports['master'].lose='management-release'
        denied(lambda:driver.release(lab,'qualified-fence',ready),'lost release reply not injected')
        assert barrier.get(store,lab)['phase']=='releasing'
        denied(lambda:store.prepare(restart,targets['master']['target'],targets['master']['journal_id']),'coordinator start crossed incomplete release')
        reopen_store()
        sealed=deepcopy(barrier.get(store,lab)['readiness'])
        events=deepcopy({host:transport.events for host,transport in transports.items()})
        def unavailable_readiness(*args):raise RuntimeError('injected current readiness unavailable')
        denied(lambda:driver.release(lab,'qualified-fence',unavailable_readiness),'recovery ignored missing current readiness')
        assert barrier.get(store,lab)['phase']=='releasing' and barrier.get(store,lab)['readiness']==sealed
        assert {host:transport.events for host,transport in transports.items()}==events
        denied(lambda:clients['worker'].plan_node(start),'unreleased worker admitted workload after failed readiness')
        assert driver.release(lab,'qualified-fence',ready)['phase']=='released'
        assert barrier.get(store,lab)['readiness']==sealed
        assert barrier.get(store,lab)['release_checks']=={'master':2,'worker':1}
        report['release_recovery']={'original_attestation_preserved':True,'failed_reobservation_sent_no_remote_release':True,
                                    'worker_remained_fenced':True,'checks':barrier.get(store,lab)['release_checks']}
        report['checks'].append('held fence survives actual runtime kill; partial provisioning seal cannot cancel; lost release reply reobserves immutable readiness attestation before every host release')
        drive(restart);new=api.inspect(name)['Id'];container_ids.append(new)
        assert new!=cid
        wait_for(lambda:'READY' in command(['docker','logs',new]))
        drive(shutdown(3,'final-stop'))
        final=clients['master'].inspect_node(lab,'vd')
        assert final['revision']==4 and final['container_state']=='absent' and final['workload']['generation']==2
        report['checks'].append('stopped spec/generation retained through fence; explicit restart creates generation2; ordinary final stop revision4')
        report['final_workload']=final;report['targets']=targets;report['status']='passed'
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:
        errors=[]
        # Workloads are cleaned only through their original generation-aware
        # runtime. Preserve daemons and evidence if that cannot be verified.
        try:
            if api.inspect(name) is not None:
                view=clients['master'].inspect_node(lab,'vd')
                if view['operation'] is not None:raise RuntimeError('pending workload requires tracked recovery')
                drive(shutdown(view['revision'],'fixture-cleanup'))
            if api.inspect(name) is not None:raise RuntimeError('workload cleanup incomplete')
        except Exception as error:errors.append(type(error).__name__+': '+str(error))
        if not errors:
            for service in reversed(list(services.values())):
                try:service.stop()
                except Exception as error:errors.append(type(error).__name__+': '+str(error))
        if store is not None:store.close()
        report['cleanup']={'verified':not errors and all(api.inspect(cid) is None for cid in container_ids),
                           'errors':errors,'workload_ids':container_ids,
                           'daemons_stopped':all(s.process is None for s in services.values())}
        report['events']={h:t.events for h,t in transports.items()}
        if errors:report['status']='failed'
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(root/'report.json',flush=True)
    assert report['cleanup']['verified']
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True);parser.add_argument('--image',required=True)
    args=parser.parse_args();run(args.image)
