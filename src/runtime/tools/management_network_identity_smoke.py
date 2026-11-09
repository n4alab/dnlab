#!/usr/bin/env python3
"""Local Docker/dnlab-vrf gate with durable fixture intent and qualified cleanup.

Creates only token-scoped management networks, kernel infrastructure and one
native Python canary. Never installs the plugin or operates on existing labs.
"""
import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'multinode'))
from dnlab_multinode.services.management_host import Worker, execute, context, signature
from dnlab_multinode.services.management_network_host import NetworkGuard, Docker, desired, plugin_state, NetworkError
from dnlab_multinode.services import netsetup
from dnlab_multinode.services.mgmt_network import _expected_network

PLUGIN='/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py'
STATE='/var/lib/dnlab-vrf-plugin/state.json'


def run(output,image,plugin_sha,*,custom_gateway=False):
    if os.geteuid()!=0:raise RuntimeError('root required')
    if not re.fullmatch('sha256:[0-9a-f]{64}',image):raise RuntimeError('immutable image ID required')
    if hashlib.sha256(Path(PLUGIN).read_bytes()).hexdigest()!=plugin_sha:raise RuntimeError('installed plugin fingerprint differs')
    root=Path(output);root.mkdir(mode=0o700,parents=True,exist_ok=False);token=uuid.uuid4().hex[:8]
    docker=Docker('/var/run/docker.sock');workers=[];guards=[];container=None;replacement=None;failure=None
    intent=dict(token=token,image=image,context=context(),workers=[],container=None,replacement=None)
    report=dict(status='running',checks=[],plugin_sha256=plugin_sha)
    image_proof=docker.call('GET','/images/'+image+'/json')
    if image_proof.get('Id')!=image or image_proof.get('Config',{}).get('Volumes'):raise RuntimeError('pinned image proof/anonymous volumes differ')
    source_root=Path(__file__).resolve().parents[3]
    report['sources']={name:hashlib.sha256((source_root/name).read_bytes()).hexdigest() for name in ('src/runtime/tools/management_network_identity_smoke.py','src/multinode/dnlab_multinode/services/management_host.py','src/multinode/dnlab_multinode/services/management_network_host.py','src/multinode/dnlab_multinode/services/netsetup.py','src/multinode/dnlab_multinode/services/mgmt_network.py')}
    baseline=plugin_state(STATE)
    def save(name,value):
        p=root/name
        with p.open('w') as stream:json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def checkpoint():save('intent.json',intent);save('report.json',report)
    save('plugin-before.json',baseline);checkpoint()
    netsetup.PATHS=SimpleNamespace(management_journal_dir=str(root/'journal'),docker_socket='unix:///var/run/docker.sock')
    class Transport:
        def run_input(self,command,payload,timeout):
            p=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout)
            if p.returncode:raise RuntimeError('standalone worker: '+p.stderr[-3500:])
            return p.stdout
    transport=Transport()
    def invoke(index,action):return netsetup.invoke(transport,'network-'+action,workers[index].plan,networks=guards[index].networks)
    def checked_container():
        value=docker.call('GET','/containers/'+container+'/json')
        if value['Id']!=container or value['Image']!=image or value['Config']['Labels']!=intent['container']['labels']:
            raise RuntimeError('fixture canary identity changed')
        return value
    def recover_canary():
        nonlocal container
        birth=intent.get('container')
        if container is not None or not birth or birth.get('phase')=='cleaned':return
        value=docker.call('GET','/containers/'+birth['name']+'/json',absent=True)
        if value is None:return
        if (value['Name']!='/'+birth['name'] or value['Image']!=image or value['Config']['Labels']!=birth['labels']
                or value['Config']['Entrypoint']!=birth['config']['Entrypoint'] or value['Config']['Cmd']!=birth['config']['Cmd']
                or value['HostConfig']['NetworkMode']!=birth['config']['HostConfig']['NetworkMode']):
            raise RuntimeError('pending fixture canary birth cannot be qualified')
        container=value['Id'];birth['id']=container;checkpoint()
    def remove_canary():
        recover_canary()
        if container is None:return
        value=checked_container()
        if value['State']['Running']:
            docker.call('POST','/containers/'+container+'/kill?signal=SIGTERM')
            result=docker.call('POST','/containers/'+container+'/wait?condition=not-running')
            if result.get('StatusCode')!=0:raise RuntimeError('canary did not stop cleanly')
        checked_container();docker.call('DELETE','/containers/'+container+'?force=false')
    def snapshot(index):
        w,g=workers[index],guards[index];r=w.read();row=r['networks']['default'];v=g.observe(row)
        return dict(id=v['Id'],network={k:v[k] for k in ('Name','Labels','Options','IPAM','EnableIPv6','Containers')},
            links={n:signature(w.links()[n]) for n in w.desired()},context=r['context'])
    try:
        links=json.loads(execute(['ip','-j','-d','link','show']))
        occupied_tables={v.get('linkinfo',{}).get('info_data',{}).get('table') for v in links}
        occupied_tables.update(v.get('table') for v in json.loads(execute(['ip','-j','route','show','table','all'])))
        occupied_vnis={v.get('linkinfo',{}).get('info_data',{}).get('id') for v in links if v.get('linkinfo',{}).get('info_kind')=='vxlan'}
        tables=[v for v in range(49000,51000) if v not in occupied_tables][:2]
        vnis=[v for v in range(16000000,16001000) if v not in occupied_vnis][:2]
        if len(tables)!=2 or len(vnis)!=2:raise RuntimeError('fixture table/VNI pool unavailable')
        for index,suffix in enumerate(('control','test')):
            lab='mgate-'+token+'-'+suffix;vrf='drsv'+token+str(index);bridge='drsb'+token+str(index);vx='drsx'+token+str(index)
            p=dict(lab=lab,generation=uuid.uuid4().hex,vrf=vrf,table=tables[index],segments={'default':dict(bridge=bridge,vxlan=vx,vni=vnis[index],underlay='lo',local='127.0.0.1',remotes=[],address='198.19.240.1/24')})
            expected=dict(driver='dnlab-vrf',ipam_driver='dnlab-vrf',network=lab+'-mgmt',bridge=bridge,vrf=vrf,lab=lab,
                ipv4_subnet='198.19.240.0/24',ipv4_gateway='198.19.240.1',ipv6_subnet='2001:db8:240::/64',ipv6_gateway='2001:db8:240::254',
                host_index=0,host_count=1,reserved=['198.19.240.1','198.19.240.254'],labels={'io.dnlab.managed':'mgmt-vrf','io.dnlab.lab':lab})
            if custom_gateway:
                # Exercise the production reservation generator on both labs;
                # only the test lab changes its manually attached JH gateway.
                topology=SimpleNamespace(name=lab,all_hosts={'master':None},mgmt=SimpleNamespace(
                    network=lab+'-mgmt',bridge=bridge,ipv4_subnet='198.19.240.0/24',
                    ipv4_gw='198.19.240.2' if index else '198.19.240.254',docker_ipv4_gw='198.19.240.1',
                    ipv6_subnet='2001:db8:240::/64',ipv6_gw='2001:db8:240::254'))
                expected=_expected_network(topology,'master');p['vrf']=expected['vrf']
            w=Worker(p,directory=root/'journal');g=NetworkGuard(w,{'default':expected})
            workers.append(w);guards.append(g);intent['workers'].append(dict(plan=p,networks=g.networks));checkpoint()
        # All kernel and network preflights precede the first fixture allocation.
        for i,w in enumerate(workers):w.operate('preflight-provision');invoke(i,'preflight')
        for i,w in enumerate(workers):w.operate('provision')
        invoke(0,'ensure');control=snapshot(0);save('control-before.json',control)
        # Inject response loss after actual Docker creation, before ID persistence.
        original=guards[1].docker.create
        def lost(config):original(config);raise RuntimeError('injected lost Docker create response')
        guards[1].docker.create=lost
        try:guards[1].operate('ensure')
        except RuntimeError as error:
            if 'injected lost' not in str(error):raise
        else:raise AssertionError('lost response not injected')
        guards[1].docker.create=original
        assert workers[1].read()['networks']['default']['id'] is None
        invoke(1,'recover');old=workers[1].read()['networks']['default']['id'];invoke(1,'ensure')
        assert workers[1].read()['networks']['default']['id']==old;report['checks'].append('lost create response recovered without replacement')
        invoke(1,'mark-used')
        name='drsp-mgmt-'+token;labels={'org.dnlab.fixture':token};nonce=uuid.uuid4().hex;labels['org.dnlab.fixture.birth']=nonce
        code="import signal,time;signal.signal(signal.SIGTERM,lambda *a:exit(0));__import__('pathlib').Path('/tmp/fixture-ready').write_text('ready');print('READY',flush=True);time.sleep(300)"
        config=dict(Image=image,Entrypoint=['python3','-u','-c',code],Cmd=[],Labels=labels,
            HostConfig={'NetworkMode':old},NetworkingConfig={'EndpointsConfig':{old:{'IPAMConfig':{'IPv4Address':'198.19.240.10','IPv6Address':'2001:db8:240::10'}}}})
        if custom_gateway:
            config['NetworkingConfig']['EndpointsConfig'][old]['IPAMConfig'].pop('IPv4Address')
        intent['container']=dict(name=name,labels=labels,config=config,id=None);checkpoint()
        value=docker.call('POST','/containers/create?name='+name,config);container=value['Id'];intent['container']['id']=container;checkpoint()
        checked_container();docker.call('POST','/containers/'+container+'/start')
        for _ in range(100):
            if checked_container()['State']['Running']:
                # Readiness is observed via the running process installing a
                # healthcheck-independent signal handler before creating a file.
                exec_cfg=dict(AttachStdout=True,AttachStderr=True,Cmd=['python3','-c',"import pathlib;assert pathlib.Path('/tmp/fixture-ready').exists()"])
                # See command adjustment below; bounded exit status is authoritative.
                ex=docker.call('POST','/containers/'+container+'/exec',exec_cfg)['Id']
                docker.call('POST','/exec/'+ex+'/start',{'Detach':True,'Tty':False})
                for _ in range(20):
                    state=docker.call('GET','/exec/'+ex+'/json')
                    if not state['Running']:break
                    time.sleep(.02)
                if state.get('ExitCode')==0:break
            time.sleep(.1)
        else:raise RuntimeError('canary readiness timed out')
        if custom_gateway:
            network=checked_container()['NetworkSettings']['Networks']
            endpoints=[v for v in network.values() if v['NetworkID']==old]
            if len(endpoints)!=1:raise RuntimeError('custom gateway canary network binding differs')
            allocated=endpoints[0]['IPAddress'];reserved=guards[1].networks['default']['reserved']
            if allocated!='198.19.240.3' or allocated in reserved or '198.19.240.2' not in reserved:
                raise RuntimeError('custom gateway reservation not honored: '+json.dumps({'allocated':allocated,'reserved':reserved}))
            assert '198.19.240.2' not in guards[0].networks['default']['reserved']
            report['custom_gateway_ipam']={'configured_gateway':'198.19.240.2',
                'allocated_dynamic_ipv4':allocated,'reserved':reserved,'control_default_unchanged':True,
                'gateway_excluded_before_spawn':True,'scope':'IPAM allocation; no jumphost guest traffic'}
            report['checks'].append('production reservation intent excludes custom gateway from dynamic Docker allocation; default control preserved')
        try:invoke(1,'cleanup')
        except RuntimeError:report['checks'].append('attached endpoint blocks cleanup')
        else:raise AssertionError('cleanup accepted active endpoint')
        remove_canary();container=None;intent['container']['phase']='cleaned';checkpoint()
        # Explicit fixture deletion of its own qualified original network.
        row=workers[1].read()['networks']['default'];guards[1].observe(row);docker.delete(old)
        for action in ('ensure','recover'):
            try:invoke(1,action)
            except RuntimeError:pass
            else:raise AssertionError('missing used network silently recreated')
        operation_id=uuid.uuid4().hex
        guards[1].docker.create=lost
        try:guards[1].operate('restore',operation_id)
        except RuntimeError as error:
            if 'injected lost' not in str(error):raise
        else:raise AssertionError('restore create response loss not injected')
        guards[1].docker.create=original
        nonce=workers[1].read()['networks']['default']['nonce']
        invoke(1,'recover');new=workers[1].read()['networks']['default'];assert new['id']!=old and new['history'][0]['id']==old
        assert new['nonce']==nonce and len(new['history'])==1
        report['checks'].append('restore response loss recovered with original operation and nonce')
        report['checks'].append('explicit restore keeps logical definitions and archives original Docker generation')
        # A separate fixture-owned replacement must be preserved by the guard.
        guards[1].observe(new);docker.delete(new['id']);payload=copy.deepcopy(guards[1].config(new))
        payload['Labels']['org.dnlab.fixture.replacement']=uuid.uuid4().hex
        intent['replacement']=dict(config=payload,id=None);checkpoint();replacement=docker.create(payload)['Id'];intent['replacement']['id']=replacement;checkpoint()
        for action in ('ensure','cleanup','restore'):
            try:invoke(1,action)
            except RuntimeError:pass
            else:raise AssertionError('replacement generation accepted')
        assert docker.inspect(replacement)['Id']==replacement
        report['checks'].append('replacement refused and preserved')
        value=docker.inspect(replacement)
        if value['Labels']!=payload['Labels'] or value['IPAM']!=payload['IPAM']:raise RuntimeError('replacement fixture ownership changed')
        docker.delete(replacement);replacement=None;intent['replacement']['phase']='cleaned';checkpoint()
        after=snapshot(0);save('control-after.json',after);assert control==after
        report['checks'].append('control lab unchanged with overlapping IPv4/IPv6 subnet')
        delete_control=guards[0].docker.delete
        def lost_delete(identity):delete_control(identity);raise RuntimeError('injected lost Docker delete response')
        guards[0].docker.delete=lost_delete
        try:guards[0].operate('cleanup')
        except RuntimeError as error:
            if 'injected lost' not in str(error):raise
        else:raise AssertionError('delete response loss not injected')
        guards[0].docker.delete=delete_control
        invoke(0,'recover');assert workers[0].read()['networks']['default']['phase']=='cleaned'
        report['checks'].append('lost delete response recovered as cleanup without creation')
    except BaseException as error:
        failure=error;report['error']=str(error);report['error_type']=type(error).__name__
        save('failure-links.json',json.loads(execute(['ip','-j','-d','link','show'])))
        save('failure-plugin.json',plugin_state(STATE))
        for i,g in enumerate(guards):
            try:save(f'failure-network-{i}.json',docker.inspect(g.networks['default']['network']))
            except Exception as error:save(f'failure-network-{i}.json',dict(error=str(error)))
    finally:
        cleanup=[]
        try:
            remove_canary();container=None
        except Exception as error:cleanup.append(dict(container_error=str(error)))
        if replacement is not None:
            try:
                value=docker.inspect(replacement)
                if value and value['Labels']==intent['replacement']['config']['Labels']:docker.delete(replacement)
                else:raise RuntimeError('replacement fixture proof differs')
            except Exception as error:cleanup.append(dict(replacement_error=str(error)))
        for i,w in reversed(list(enumerate(workers))):
            try:
                if w.read():
                    guards[i].operate('cleanup');guards[i].operate('verify-cleaned');w.cleanup();w.operate('verify-cleaned')
                cleanup.append(dict(lab=w.plan['lab'],status='cleaned'))
            except Exception as error:cleanup.append(dict(lab=w.plan['lab'],error=str(error)))
        save('cleanup.json',cleanup)
        after=plugin_state(STATE);save('plugin-after.json',after)
        report['plugin_baseline_unchanged']=after==baseline
        report['cleanup_verified']=not any('error' in k for row in cleanup for k in row) and after==baseline
        report['installed_plugin_unchanged']=hashlib.sha256(Path(PLUGIN).read_bytes()).hexdigest()==plugin_sha
        report['status']='passed' if failure is None and report['cleanup_verified'] and report['installed_plugin_unchanged'] else 'failed'
        checkpoint()
    if failure:raise failure
    if report['status']!='passed':raise RuntimeError('gate cleanup/baseline verification failed')
    print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--image',required=True);parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--custom-gateway',action='store_true');args=parser.parse_args()
    run(args.output,args.image,args.plugin_sha256,custom_gateway=args.custom_gateway)
