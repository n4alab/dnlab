#!/usr/bin/env python3
"""Opt-in bridge API gate with native Docker VDs in an isolated anchor namespace."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_runtime.backend import Backend,Docker,Linux
from dnlab_runtime.bridge import BridgeLinux,BridgeManager
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from dnlab_runtime.transport import Client
from link_api_smoke import LocalCommand,cleanup_worker,docker
from smoke import wait_for,operation
from vxlan_smoke import command


class FixtureLinux(Linux):
    def __init__(self,path):
        self.path=path;self.fd=os.open(path,os.O_RDONLY)
        info=os.fstat(self.fd);self.identity=(info.st_dev,info.st_ino)
    def network_identity(self):
        info=os.stat(self.path)
        if (info.st_dev,info.st_ino)!=self.identity:raise Conflict('fixture anchor namespace changed')
        return {**super().network_identity(),'device':info.st_dev,'inode':info.st_ino}
    def run(self,argv,**kwargs):
        self.network_identity();inherited=kwargs.pop('pass_fds',())
        return super().run(['nsenter',f'--net=/proc/self/fd/{self.fd}','--',*argv],pass_fds=(*inherited,self.fd),**kwargs)


def run(runtime_image,workload_image,*,replay_cancel=False,coordinated_stop=False):
    root=Path(tempfile.mkdtemp(prefix='dnlab-bridge-api-'));root.chmod(0o700)
    state=root/'state';state.mkdir(mode=0o700);sockets=root/'run';sockets.mkdir(mode=0o700)
    token=uuid.uuid4().hex[:8];lab='bridge-api-'+token
    anchor_name='drsp-bridge-anchor-'+token;daemon_name='drsp-bridge-daemon-'+token
    report={'scope':'local-image-bridge-API-native-VDs-isolated-anchor','status':'running',
            'runtime_image':runtime_image,'workload_image':workload_image,
            'real_ssh_qualified':False,'cross_host_qualified':False,'nos_qualified':False,'checks':[]}
    api=Docker();anchor=daemon=linux=backend=None;requests={};specs={};created_nodes=[];workers=[];extra_workloads=[]
    client=Client(str(sockets/'runtime.sock'))
    adapter=RuntimeClient(LocalCommand(),socket_path=client.socket_path,container_name=daemon_name)
    identity=BridgeIdentity(lab,'l0')
    ready='READY-'+token
    code="import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print("+repr(ready)+",flush=True); time.sleep(3600)"

    def service_stop():
        observed=api.inspect(daemon['id'])
        if not observed or observed['Name']!='/'+daemon_name or observed['Image']!=runtime_image or observed['Config']['Labels'].get('io.dnlab.spike')!=lab:
            raise Conflict('fixture daemon ownership changed')
        docker('stop','--time','30',daemon['id'])
    def service_start():
        api.start(daemon['id']);wait_for(lambda:client.request('GET','/v1/capabilities'))
    def link_action(action,request_id):
        raw={**link,'action':action,'request_id':request_id}
        if action!='create':raw.pop('spec')
        accepted=adapter.submit(raw);return adapter.wait(accepted['id'],timeout=20)
    def native_ping(expected=True):
        left=backend.verify(requests['vd1'],specs['vd1']);backend.verify(requests['vd2'],specs['vd2'])
        result=command(['nsenter',f'--net=/proc/{left["State"]["Pid"]}/ns/net','--','ping','-n','-I','eth1','-c','2','-W','1','-s','1372','198.19.207.2'],check=False)
        assert (result.returncode==0)==expected,result.stdout+result.stderr
        return {'returncode':result.returncode,'stdout':result.stdout}
    try:
        anchor_id=docker('create','--name',anchor_name,'--network','none','--label','io.dnlab.spike='+lab,
                         '--entrypoint','python3',workload_image,'-c',code)
        anchor={'id':anchor_id,'name':anchor_name};api.start(anchor_id)
        wait_for(lambda:ready in docker('logs',anchor_id))
        anchor_pid=api.inspect(anchor_id)['State']['Pid']
        linux=FixtureLinux(f'/proc/{anchor_pid}/ns/net');backend=Backend(api,linux)
        daemon_id=docker('create','--name',daemon_name,'--label','io.dnlab.spike='+lab,
                         '--privileged','--network','container:'+anchor_id,'--pid','host',
                         '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                         '--mount',f'type=bind,src={root},dst={root}',
                         '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
                         '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id',
                         runtime_image,'--socket',client.socket_path,'serve','--state-dir',str(state))
        daemon={'id':daemon_id,'name':daemon_name};service_start()
        assert 'bridge' in adapter.qualify(kind='bridge')['link_kinds']
        if coordinated_stop:
            from workload_generation_probe import probe
            probe(api=api,client=client,state=state,lab=lab,image=workload_image,report=report)
            from inspect_transition_probe import probe
            probe(root=root,state=state,lab=lab,daemon=daemon,anchor=anchor,api=api,client=client,adapter=adapter,
                  image=workload_image,runtime_image=runtime_image,service_start=service_start,service_stop=service_stop,
                  workers=workers,report=report,extra_workloads=extra_workloads)
        for index in (1,2):
            node='vd'+str(index)
            spec={'kind':'linux','image':workload_image,'container_name':'drsp-bridge-'+node+'-'+token,
                  'command':['python3','-c',code],'stop_timeout':5,
                  'endpoints':[{'host_interface':'drsp'+token+str(index),'node_interface':'eth1','mtu':1450}]}
            if coordinated_stop and index==1:
                spec['command']=['python3','-c',"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("+repr(ready)+",flush=True); time.sleep(3600)"]
                spec['stop_timeout']=1
            raw={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'start-'+node,'expected_revision':0,'action':'start','spec':spec}
            specs[node]=spec;requests[node]=raw;created_nodes.append(node)
            operation(client,client.request('POST','/v1/operations',raw)['id'])
            observed=backend.verify(raw,spec);wait_for(lambda:ready in docker('logs',observed['Id']))
            command(['nsenter',f'--net=/proc/{observed["State"]["Pid"]}/ns/net','--','ip','address','add',f'198.19.207.{index}/24','dev','eth1'])
        link={'schema_version':1,'kind':'bridge','lab_id':lab,'link_id':'l0','action':'create','request_id':'create',
              'endpoints':[{'node_id':node,'host_interface':specs[node]['endpoints'][0]['host_interface'],'expected_node_revision':1} for node in ('vd1','vd2')],
              'spec':{'mtu':1450}}
        assert adapter.plan(link)['affected_nodes']==['vd1','vd2']
        before={node:backend.verify(requests[node],specs[node])['Id'] for node in ('vd1','vd2')}
        created=link_action('create','create');report['initial_ping']=native_ping()
        assert created['kind']=='bridge' and created['affected_nodes']==['vd1','vd2']
        link_action('create','retry');service_stop();service_start()
        assert adapter.submit(link)['id']==created['id'];report['restart_ping']=native_ping()
        for node in ('vd1','vd2'):
            stop={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'blocked-'+node,'expected_revision':1,'action':'stop'}
            try:client.request('POST','/v1/operations',stop)
            except RuntimeErrorBase as error:assert 'before stopping' in str(error)
            else:raise AssertionError('bridge owner stop accepted')
        report['checks'].extend(['two committed native VD endpoints','IPv4 traffic','retry and daemon restart preserve workloads/link','both node stop guards'])
        third_spec={**specs['vd1'],'container_name':'drsp-bridge-vd3-'+token,
                    'command':['python3','-c',code],
                    'endpoints':[{'host_interface':'drsp'+token+'3','node_interface':'eth1','mtu':1450}]}
        third_start={**requests['vd1'],'node_id':'vd3','request_id':'start-vd3','spec':third_spec}
        specs['vd3']=third_spec;requests['vd3']=third_start;created_nodes.append('vd3')
        operation(client,client.request('POST','/v1/operations',third_start)['id'])
        third=backend.verify(third_start,third_spec);wait_for(lambda:ready in docker('logs',third['Id']))
        operation(client,client.request('POST','/v1/operations',{'schema_version':1,'lab_id':lab,'node_id':'vd3','request_id':'stop-vd3','expected_revision':1,'action':'stop'})['id'])
        report['spawn_stop_other_vd_ping']=native_ping()
        report['checks'].append('spawn/stop third VD preserves active bridge and original workloads')
        from endpoint_preflight_probe import probe
        probe(api=api,client=client,state=state,lab=lab,image=workload_image,linux=linux,
              report=report,native_ping=native_ping,extra_workloads=extra_workloads)
        report['workload_ids_preserved']=all(backend.verify(requests[node],specs[node])['Id']==before[node] for node in before)
        assert report['workload_ids_preserved']
        if replay_cancel:
            from link_api_replay_probe import probe
            probe(root=root,report=report,state=state,runtime_image=runtime_image,lab=lab,link=link,
                  daemon_start=service_start,daemon_stop=service_stop,adapter=adapter,native_ping=native_ping,
                  link_action=link_action,peer_verify=lambda:[backend.verify(requests[node],specs[node]) for node in ('vd1','vd2')],
                  command=command,docker=docker,workers=workers,network_mode='container:'+anchor['id'])
        if coordinated_stop:
            from daemon_cleanup_probe import probe
            probe(root=root,report=report,lab=lab,daemon=daemon,api=api,client=client,backend=backend,
                  requests=requests,specs=specs,extra_workloads=extra_workloads,service_start=service_start)
        if coordinated_stop:
            from coordinated_stop_probe import probe
            probe(root=root,report=report,state=state,lab=lab,daemon=daemon,anchor=anchor,api=api,
                  backend=backend,requests=requests,specs=specs,runtime_image=runtime_image,
                  client=client,service_start=service_start,service_stop=service_stop,native_ping=native_ping,workers=workers)
        else:
            link_action('delete','delete');report['deleted_ping']=native_ping(False)
            link_action('create','recreate');report['recreated_ping']=native_ping()
            link_action('delete','final-delete')
        report['final_link_states']={node:adapter.invoke('link-inspect',lab,'l0',specs[node]['endpoints'][0]['host_interface']) for node in ('vd1','vd2')}
        assert all(value['committed_state']=='deleted' and value['runtime_phase']=='cleaned' and value['kernel_state']=='absent' for value in report['final_link_states'].values())
        for node in ('vd1','vd2'):
            if coordinated_stop and node=='vd1':continue
            stop={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'stop-'+node,'expected_revision':1,'action':'stop'}
            operation(client,client.request('POST','/v1/operations',stop)['id'])
            assert backend.inspect(requests[node],specs[node]) is None
        report['checks'].extend(['both endpoint states committed together','safe native stop'])
        if not coordinated_stop:report['checks'].extend(['delete breaks traffic','recreate restores traffic'])
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        try:
            if daemon:service_stop()
            for worker in workers:cleanup_worker(api,worker,runtime_image,lab)
            if extra_workloads:
                from dnlab_runtime.engine import Engine
                from dnlab_runtime.workload_generation import latest
                extra_journal=Journal(state)
                try:
                    guarded=Backend(api,linux);Engine(extra_journal,guarded)
                    for owner,name in extra_workloads:
                        birth=latest(extra_journal,owner)
                        if birth is None:
                            assert api.inspect(name) is None
                            continue
                        original=extra_journal.get(birth['creator'],private=True)['payload']
                        spec=original['spec']
                        if guarded.inspect(owner,spec):
                            guarded.stop(owner,spec,force=True)
                            guarded.delete_endpoints(owner,spec);guarded.remove(owner,spec)
                        assert api.inspect(name) is None
                finally:extra_journal.close()

            if backend and state.joinpath('journal.sqlite3').exists():
                journal=Journal(state)
                try:
                    manager=BridgeManager(journal,BridgeLinux(linux))
                    if manager.row(identity.digest):manager.delete(identity)
                finally:journal.close()
            if backend:
                for node in reversed(created_nodes):
                    if backend.inspect(requests[node],specs[node]):
                        backend.stop(requests[node],specs[node],force=True)
                        backend.delete_endpoints(requests[node],specs[node]);backend.remove(requests[node],specs[node])
                    else:backend.delete_endpoints(requests[node],specs[node])
                assert linux.link(identity.kernel_name) is None
                assert all(linux.link(specs[node]['endpoints'][0]['host_interface']) is None for node in created_nodes)
            if daemon:cleanup_worker(api,daemon,runtime_image,lab)
            if linux:os.close(linux.fd)
            if anchor:cleanup_worker(api,anchor,workload_image,lab)
            assert all(api.inspect(item['id']) is None for item in (daemon,anchor) if item)
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps({'report':str(root/'report.json'),'status':report.get('status'),'error':report.get('error'),'cleanup_verified':report.get('cleanup_verified')}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--runtime-image',required=True);parser.add_argument('--image',default='python:3.13-slim')
    parser.add_argument('--replay-cancel',action='store_true');parser.add_argument('--coordinated-stop',action='store_true');args=parser.parse_args()
    if not args.execute:
        print(json.dumps({'mutations_performed':False,'creates':'isolated anchor, runtime daemon, two native VD and owned bridge'}));return
    if os.geteuid()!=0:raise RuntimeError('gate requires root')
    runtime=docker('image','inspect','--format','{{.Id}}',args.runtime_image)
    workload=docker('image','inspect','--format','{{.Id}}',args.image)
    run(runtime,workload,replay_cancel=args.replay_cancel,coordinated_stop=args.coordinated_stop)


if __name__=='__main__':main()
