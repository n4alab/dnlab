#!/usr/bin/env python3
"""Opt-in image API gate with one Linux VD and an isolated remote namespace peer."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(SOURCE.parent / 'multinode'))
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_runtime.backend import Backend, Linux
from dnlab_runtime.journal import Journal
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase
from dnlab_runtime.transport import Client
from dnlab_runtime.vxlan import VxlanLinux, VxlanManager, link_signature
from smoke import operation, wait_for
from vxlan_smoke import NamespaceLinux, command, ip


class LocalCommand:
    """Execute the adapter's CLI command locally; this does not test SSH."""
    def run(self, text):
        return subprocess.run(['/bin/sh', '-c', text], check=True, text=True,
                              capture_output=True, timeout=20).stdout.strip()


def docker(*args):
    return command(['docker', *args]).stdout.strip()


def cleanup_worker(api, worker, runtime_image, lab):
    """An HTTP 404 is absence; other inspection failures must propagate."""
    def inspect():
        value=api.inspect(worker['id'])
        if value is not None and (value['Id']!=worker['id']
                or value['Name']!='/'+worker['name'] or value['Image']!=runtime_image
                or value['Config']['Labels'].get('io.dnlab.spike')!=lab):
            raise RuntimeError('fixture worker ownership changed')
        return value
    value=inspect()
    if value is None:return
    if value['State']['Running']:
        api.signal(worker['id'],'SIGKILL')
        deadline=time.monotonic()+15
        while True:
            value=inspect()
            if value is None:return
            if not value['State']['Running']:break
            if time.monotonic()>=deadline:raise RuntimeError('fixture worker exit timeout')
            time.sleep(.05)
    api.remove(worker['id'])
    if inspect() is not None:raise RuntimeError('fixture worker remains after removal')


def run(runtime_image, workload_image, *, replay_cancel=False):
    root = Path(tempfile.mkdtemp(prefix='dnlab-link-api-'))
    root.chmod(0o700)
    state, sockets = root/'state', root/'run'
    state.mkdir(mode=0o700); sockets.mkdir(mode=0o700)
    token = uuid.uuid4().hex[:8]
    lab = 'link-api-'+token
    daemon_name = 'dnlab-link-api-daemon-'+token
    endpoint, underlay, remote_endpoint = 'drsp'+token+'a', 'drsp'+token+'u', 'drsp'+token+'b'
    names = {'remote':'drsp-api-r-'+token, 'guest':'drsp-api-g-'+token}
    report = {'scope':'local-image-api-native-VD-and-namespace-peer',
              'runtime_image':runtime_image,'workload_image':workload_image,
              'real_ssh_qualified':False,'cross_host_qualified':False,'nos_qualified':False,
              'namespaces':names,'checks':[], 'status':'running'}
    backend = Backend()
    daemon = None
    workers = []
    owned_ns = {}
    underlay_identity = None
    remote_journal = remote_manager = remote_identity = None
    client = Client(str(sockets/'runtime.sock'))
    adapter = RuntimeClient(LocalCommand(),socket_path=client.socket_path,container_name=daemon_name)
    spec = {'kind':'linux','image':workload_image,'container_name':'dnlab-link-api-vd-'+token,
            'command':['python3','-c',"import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print('READY',flush=True); time.sleep(3600)"],
            'stop_timeout':5,'endpoints':[{'host_interface':endpoint,'node_interface':'eth1','mtu':1450}]}
    start = {'schema_version':1,'lab_id':lab,'node_id':'vd1','request_id':'start',
             'expected_revision':0,'action':'start','spec':spec}
    second_spec={**spec,'container_name':'dnlab-link-api-vd2-'+token,
                 'endpoints':[{'host_interface':'drsp'+token+'c','node_interface':'eth1','mtu':1450}]}
    second_start={**start,'node_id':'vd2','request_id':'start-second','spec':second_spec}
    link = {'schema_version':1,'lab_id':lab,'node_id':'vd1','link_id':'link1',
            'request_id':'link-create','expected_node_revision':1,'host_interface':endpoint,
            'action':'create','spec':{'vni':3021,'underlay':underlay,'local':'198.18.202.1','remote':'198.18.202.2','mtu':1450}}
    host_identity = VxlanIdentity(lab,'link1',endpoint,3021)
    before_containers = set(docker('ps','-aq').splitlines())

    def save():
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')

    def service_stop():
        if daemon:
            observed = json.loads(docker('inspect',daemon))[0]
            if observed['Name'] != '/'+daemon_name or observed['Image'] != runtime_image or observed['Config']['Labels'].get('io.dnlab.spike') != lab:
                raise RuntimeError('daemon ownership changed')
            docker('stop','--time','30',daemon)

    def service_start():
        docker('start',daemon)
        wait_for(lambda:client.request('GET','/v1/capabilities'))

    def native_ping(expected=True):
        observed = backend.inspect(start,spec)
        backend.verify(start,spec)
        result = command(['nsenter',f'--net=/proc/{observed["State"]["Pid"]}/ns/net','--',
                          'ping','-n','-I','eth1','-c','2','-W','1','-s','1372','198.19.102.2'],check=False)
        if (result.returncode == 0) != expected:
            raise RuntimeError('API link ICMP expectation failed: '+result.stdout+result.stderr)
        return {'returncode':result.returncode,'stdout':result.stdout}

    def link_action(action,request_id):
        request={**link,'action':action,'request_id':request_id}
        if action!='create':request.pop('spec')
        accepted=adapter.submit(request)
        return adapter.wait(accepted['id'],timeout=20)

    try:
        # Fail closed before mutations if the fixture subnet or names are occupied.
        subnet=ipaddress.ip_network('198.18.202.0/30')
        for route in json.loads(command(['ip','-j','-4','route','show','table','all']).stdout):
            destination=route.get('dst','default')
            if destination!='default' and ipaddress.ip_network(destination,strict=False).overlaps(subnet):
                raise RuntimeError('fixture underlay subnet already routed')
        for name in (endpoint,underlay,second_spec['endpoints'][0]['host_interface']):
            if backend.linux.link(name):raise RuntimeError('fixture host name occupied')
        existing=command(['ip','netns','list']).stdout
        for name in names.values():
            if name in existing:raise RuntimeError('fixture namespace name occupied')
            command(['ip','netns','add',name])
            info=os.stat('/var/run/netns/'+name)
            owned_ns[name]=(info.st_dev,info.st_ino)
            ip(name,'link','set','lo','up')
        command(['ip','link','add',underlay,'type','veth','peer','name','underlay0','netns',names['remote']])
        underlay_identity=backend.linux.link(underlay)
        command(['ip','link','set','dev',underlay,'alias','dnlab-runtime:fixture-'+lab])
        command(['ip','address','add','198.18.202.1/30','dev',underlay])
        command(['ip','link','set',underlay,'up'])
        ip(names['remote'],'address','add','198.18.202.2/30','dev','underlay0')
        ip(names['remote'],'link','set','underlay0','up')
        ip(names['remote'],'link','add',remote_endpoint,'mtu','1450','type','veth','peer','name','eth0','netns',names['guest'])
        ip(names['remote'],'link','set',remote_endpoint,'alias','dnlab-runtime:fixture-'+lab)
        ip(names['remote'],'link','set',remote_endpoint,'up')
        ip(names['guest'],'link','set','eth0','mtu','1450','up')
        ip(names['guest'],'address','add','198.19.102.2/24','dev','eth0')
        remote_journal=Journal(root/'remote-state')
        remote_manager=VxlanManager(remote_journal,VxlanLinux(NamespaceLinux(names['remote'])))
        remote_identity=VxlanIdentity(lab,'link1',remote_endpoint,3021)
        source=next(x for x in remote_manager.linux.links() if x['ifname']==remote_endpoint)
        remote_manager.create(remote_identity,source=source,underlay='underlay0',local='198.18.202.2',remote='198.18.202.1',mtu=1450)
        remote_snapshot=remote_manager.row(remote_identity.digest)['payload']
        daemon=docker('create','--name',daemon_name,'--label','io.dnlab.spike='+lab,
                      '--privileged','--network','host','--pid','host',
                      '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
                      '--mount',f'type=bind,src={root},dst={root}',
                      '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
                      '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id',runtime_image,
                      '--socket',client.socket_path,'serve','--state-dir',str(state))
        report['daemon_id']=daemon;save()
        docker('start',daemon)
        wait_for(lambda:client.request('GET','/v1/capabilities'))
        node=client.request('POST','/v1/operations',start)
        operation(client,node['id'])
        wait_for(lambda:'READY' in docker('logs',spec['container_name']))
        native=backend.inspect(start,spec)
        backend.verify(start,spec)
        command(['nsenter',f'--net=/proc/{native["State"]["Pid"]}/ns/net','--','ip','address','add','198.19.102.1/24','dev','eth1'])
        source_before=link_signature(backend.linux.link(endpoint))
        assert adapter.plan(link)['mutations_performed'] is False
        created=link_action('create','link-create')
        assert adapter.submit(link)['id']==created['id']
        report['traffic']=native_ping()
        assert adapter.invoke('link-inspect',lab,'link1',endpoint)['committed_state']=='active'
        stop={k:v for k,v in {**start,'action':'stop','request_id':'stop','expected_revision':1}.items() if k!='spec'}
        try:client.request('POST','/v1/operations',stop)
        except RuntimeErrorBase as error:
            if 'before stopping' not in str(error):raise
        else:raise RuntimeError('node stop accepted while link active')
        assert backend.inspect(start,spec)['Id']==native['Id']
        report['checks'].append('API create/dedup/inspect, ICMP and active-link stop guard')
        second=client.request('POST','/v1/operations',second_start)
        operation(client,second['id'])
        wait_for(lambda:'READY' in docker('logs',second_spec['container_name']))
        backend.verify(second_start,second_spec)
        assert backend.inspect(start,spec)['Id']==native['Id']
        assert link_signature(backend.linux.link(endpoint))==source_before
        report['second_spawn_traffic']=native_ping()
        second_stop={k:v for k,v in {**second_start,'action':'stop','request_id':'stop-second','expected_revision':1}.items() if k!='spec'}
        operation(client,client.request('POST','/v1/operations',second_stop)['id'])
        assert not backend.inspect(second_start,second_spec)
        assert not backend.linux.link(second_spec['endpoints'][0]['host_interface'])
        report['after_second_stop_traffic']=native_ping()
        report['checks'].append('second VD spawn/stop in active lab preserves first workload, endpoint and traffic')
        service_stop();docker('start',daemon)
        wait_for(lambda:client.request('GET','/v1/capabilities'))
        assert adapter.wait(created['id'],timeout=5)['phase']=='completed'
        assert adapter.submit(link)['id']==created['id']
        report['restart_traffic']=native_ping()
        report['checks'].append('daemon restart preserves link, request identity and native workload')
        if replay_cancel:
            from link_api_replay_probe import probe
            probe(root=root,report=report,state=state,runtime_image=runtime_image,
                  lab=lab,link=link,daemon_start=service_start,daemon_stop=service_stop,
                  adapter=adapter,native_ping=native_ping,link_action=link_action,
                  peer_verify=lambda:remote_manager.verify(remote_identity,remote_snapshot),
                  command=command,docker=docker,workers=workers)
        link_action('delete','link-delete')
        report['deleted_traffic']=native_ping(expected=False)
        remote_manager.verify(remote_identity,remote_snapshot)
        assert link_signature(backend.linux.link(endpoint))==source_before
        link_action('create','link-recreate')
        report['recreated_traffic']=native_ping()
        link_action('delete','link-final-delete')
        operation(client,client.request('POST','/v1/operations',stop)['id'])
        assert not backend.inspect(start,spec) and not backend.linux.link(endpoint)
        report['checks'].append('delete breaks traffic, remote peer unchanged, recreate restores traffic, safe native stop')
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error)
        raise
    finally:
        # Stop the daemon before offline recovery so only one journal owner runs.
        try:
            service_stop()
            for worker in workers:
                cleanup_worker(backend.docker,worker,runtime_image,lab)
            if state.joinpath('journal.sqlite3').exists():
                journal=Journal(state)
                try:VxlanManager(journal,VxlanLinux(Linux())).delete(host_identity)
                finally:journal.close()
            if backend.inspect(start,spec):
                backend.stop(start,spec,force=True)
                backend.delete_endpoints(start,spec)
                backend.remove(start,spec)
            else:
                backend.delete_endpoints(start,spec)
            if backend.inspect(second_start,second_spec):
                backend.stop(second_start,second_spec,force=True)
                backend.delete_endpoints(second_start,second_spec)
                backend.remove(second_start,second_spec)
            else:
                backend.delete_endpoints(second_start,second_spec)
            if remote_manager and remote_identity:remote_manager.delete(remote_identity)
            if remote_journal:remote_journal.close()
            if daemon:docker('rm',daemon)
            if underlay_identity:
                current=backend.linux.link(underlay)
                if current:
                    if any(current.get(k)!=underlay_identity.get(k) for k in ('ifindex','address','link_index')):
                        raise RuntimeError('fixture underlay ownership changed')
                    command(['ip','link','delete','dev',underlay])
            for name,identity in reversed(list(owned_ns.items())):
                info=os.stat('/var/run/netns/'+name)
                if (info.st_dev,info.st_ino)!=identity:raise RuntimeError('fixture namespace replaced')
                command(['ip','netns','delete',name])
            assert set(docker('ps','-aq').splitlines())==before_containers
            assert not backend.linux.link(endpoint) and not backend.linux.link(host_identity.kernel_name)
            assert not backend.linux.link(underlay)
            assert not backend.linux.link(second_spec['endpoints'][0]['host_interface'])
            report['cleanup_verified']=True
        except BaseException as cleanup_error:
            report['cleanup_verified']=False;report['cleanup_error']=str(cleanup_error)
            raise
        finally:
            save();print(json.dumps({'report':str(root/'report.json'),**report},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--runtime-image',default='dnlab-runtime-spike:link-api-20261012')
    parser.add_argument('--image',default='python:3.13-slim')
    parser.add_argument('--replay-cancel',action='store_true')
    args=parser.parse_args()
    if not args.execute:
        print(json.dumps({'mutations_performed':False,'scope':'one dedicated runtime daemon and two Linux VD, two isolated peer namespaces, dedicated underlay veth','checks':['API link lifecycle','ICMP','second VD spawn/stop in active lab','restart/dedup','stop guard','owned cleanup']}));return
    if os.geteuid()!=0:raise RuntimeError('live gate requires root')
    runtime=docker('image','inspect','--format','{{.Id}}',args.runtime_image)
    workload=docker('image','inspect','--format','{{.Id}}',args.image)
    run(runtime,workload,replay_cancel=args.replay_cancel)


if __name__=='__main__':main()
