#!/usr/bin/env python3
"""Opt-in local jumphost birth/attachment gate; never touches existing labs."""
import argparse
import copy
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import socket
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'multinode'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_multinode.services.jumphost_host import Worker, execute, signature, names, JumphostError
from dnlab_runtime.backend import Docker, Linux
from dnlab_multinode.services.management_host import Worker as ManagementWorker
from dnlab_multinode.services.management_network_host import NetworkGuard, desired as desired_network
from initial_management_identity_smoke import delete_fixture_interface

PLUGIN = Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
STATE = Path('/var/lib/dnlab-vrf-plugin/state.json')


def run(image, plugin_sha256, output, *, dhcp_config=None, service_gate=None, attachment_gate=None, full_management=True):
    if os.getuid() != 0: raise RuntimeError('root required')
    if not full_management: raise RuntimeError('qualified management lifecycle required')
    if hashlib.sha256(PLUGIN.read_bytes()).hexdigest() != plugin_sha256: raise RuntimeError('plugin fingerprint differs')
    docker = Docker(); linux = Linux(); token = uuid.uuid4().hex[:8]
    root = Path(output); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    lab_prefix = 'jhgate-' + token
    report = {'status': 'running', 'image': image, 'plugin_sha256': plugin_sha256,
              'scope': 'local Docker jumphost and management veth, not full GUI or multi-segment qualification', 'checks': []}
    baseline = json.loads(STATE.read_text()); (root/'plugin-baseline.json').write_text(json.dumps(baseline,indent=2)+'\n'); infra = []; networks = []; workers = []; descriptors = []; management_workers = []
    intent = {'token': token, 'infra': infra, 'networks': networks, 'labs': [], 'management': []}
    def save():
        (root/'intent.json').write_text(json.dumps(intent, indent=2)+'\n')
        (root/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    def link(name, kind, table=None):
        entry = {'name': name, 'kind': kind, 'mac': '02:fd:' + ':'.join(token[i:i+2] for i in range(0,8,2)), 'alias': lab_prefix}
        if table: entry['table'] = table
        if linux.link(name): raise RuntimeError('fixture name occupied')
        infra.append(entry); save()
        execute(['ip','link','add',name,'address',entry['mac'],'alias',entry['alias'],'type',kind] + (['table',str(table)] if table else []))
        entry['ifindex'] = linux.link(name)['ifindex']; save()
        execute(['ip','link','set',name,'alias',entry['alias']]); execute(['ip','link','set',name,'up'])
        return name
    network_guards = {}
    def network(payload):
        if docker.request('GET','/networks/'+payload['Name'],missing_ok=True): raise RuntimeError('fixture network name occupied')
        entry = {'payload': payload, 'id': None}; networks.append(entry); save()
        value = docker.request('POST','/networks/create',payload); entry['id'] = value['Id']; save()
        return entry['id']
    def free_port():
        with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
    def ssh_ready(cfg):
        deadline = time.monotonic()+30
        while True:
            try:
                with socket.create_connection(('127.0.0.1',cfg['port']),timeout=1) as s:
                    s.settimeout(1)
                    if s.recv(100).startswith(b'SSH-'): return
            except OSError: pass
            if time.monotonic()>deadline: raise RuntimeError('SSH banner not ready')
            time.sleep(.1)
    def control_signature(worker):
        r=worker.operate('read');v=worker.container(r)
        with worker.namespace(r) as fd:
            return {'id':v['Id'],'started_at':v['State']['StartedAt'], 'networks':v['NetworkSettings']['Networks'],
                    'host':signature(worker.find(names(worker.lab))), 'peer':signature(worker.find('eth1',fd))}
    try:
        occupied = {v.get('linkinfo',{}).get('info_data',{}).get('table') for v in json.loads(execute(['ip','-j','-d','link','show']))}
        occupied.update(v.get('table') for v in json.loads(execute(['ip','-j','route','show','table','all'])))
        tables=[v for v in range(46000,49000) if v not in occupied][:2]
        if len(tables)!=2: raise RuntimeError('no fixture VRF tables')
        ext_name=lab_prefix+'-external';ext_bridge='drspx'+token
        network({'Name':ext_name,'Driver':'bridge','Options':{'com.docker.network.bridge.name':ext_bridge},
                 'Labels':{'io.dnlab.spike':lab_prefix}, 'IPAM':{'Config':[{'Subnet':'198.19.230.0/24','Gateway':'198.19.230.1'}]}})
        occupied_vnis={v.get('linkinfo',{}).get('info_data',{}).get('id') for v in json.loads(execute(['ip','-j','-d','link','show'])) if v.get('linkinfo',{}).get('info_kind')=='vxlan'}
        vnis=[v for v in range(16000000,16001000) if v not in occupied_vnis][:2]
        if full_management and len(vnis)!=2: raise RuntimeError('no unused fixture management VNI')
        configs=[]
        for index,suffix in enumerate(('control','test')):
            lab=lab_prefix+'-'+suffix
            if full_management:
                vrf='drspv'+token+str(index);bridge='drspb'+token+str(index)
                plan={'lab':lab,'generation':uuid.uuid4().hex,'vrf':vrf,'table':tables[index],
                      'segments':{'default':{'bridge':bridge,'vxlan':'drspx'+token+str(index),'vni':vnis[index],
                                  'underlay':'lo','local':'127.0.0.1','remotes':[],'address':'198.19.231.1/24'}}}
                intent['management'].append(plan);save()
                management=ManagementWorker(plan,directory=root/'management-journal');management_workers.append(management)
                management.operate('preflight');management.operate('ensure')
                report['checks'].append('complete journal-owned management resources and firewall: '+suffix);save()
            else:
                vrf=link('drspv'+token+str(index),'vrf',tables[index]);bridge=link('drspb'+token+str(index),'bridge')
                execute(['ip','link','set',bridge,'master',vrf]);execute(['ip','addr','add','198.19.231.1/24','dev',bridge])
            mgmt=lab+'-mgmt'
            expected_network = dict(driver='dnlab-vrf',ipam_driver='dnlab-vrf',network=mgmt,bridge=bridge,vrf=vrf,lab=lab,
                ipv4_subnet='198.19.231.0/24',ipv4_gateway='198.19.231.1',host_index=0,host_count=1,
                reserved=['198.19.231.1','198.19.231.254'],labels={'io.dnlab.lab':lab,'io.dnlab.managed':'mgmt-vrf'})
            entry = {'payload':desired_network(expected_network),'id':None,'management_lab':lab};networks.append(entry);save()
            guard = NetworkGuard(management,{'default':expected_network});network_guards[lab] = guard
            guard.operate('preflight');guard.operate('ensure');guard.operate('mark-used')
            entry['id'] = management.read()['networks']['default']['id'];save()
            cfg={'lab':lab,'generation':uuid.uuid4().hex,'name':'drsp-jumphost-'+token+'-'+suffix,'image':image,
                'network':{'name':ext_name,'bridge':ext_bridge,'subnet':'198.19.230.0/24','gateway':'198.19.230.1'},
                'ip':'198.19.230.'+str(index+2),'bind_ip':'127.0.0.1','port':free_port(),
                'management_intent':expected_network,
                'env':{'JUMPHOST_PASSWORD':uuid.uuid4().hex,'JUMPHOST_LAB_NAME':lab}, 'dns':[],'binds':[],'dhcp':dhcp_config() if dhcp_config else '',
                'attachment':{'segment':'default','network':mgmt,'bridge':bridge,'interface':'eth1','ipv4':'198.19.231.254/24','ipv6':''}}
            intent['labs'].append({'lab':lab,'config':cfg,'journal':str(root/'journal')});save()
            configs.append(cfg);workers.append(Worker(lab,directory=root/'journal',management_directory=root/'management-journal'))
        control,test=workers
        for difference in ('subnet','ipam-driver','unqualified-origin'):
            invalid=copy.deepcopy(configs[1])
            candidate=test
            if difference=='subnet': invalid['attachment']['ipv4']='198.19.232.254/24'
            elif difference=='ipam-driver': invalid['management_intent']['ipam_driver']='default'
            else: candidate=Worker(test.lab,directory=root/'journal',management_directory=root/'unqualified-management')
            try: candidate.operate('ensure',invalid)
            except (JumphostError,OSError): pass
            else: raise RuntimeError('incompatible management admission accepted: '+difference)
            assert test.read() is None and docker.inspect(configs[1]['name']) is None
            report['checks'].append('management '+difference+' refused before birth');save()
        control.operate('ensure',configs[0]);ssh_ready(configs[0]);before=control_signature(control)
        failures={'create':True,'veth':True}
        def interrupted(argv,**kwargs):
            result=execute(argv,**kwargs)
            marker='create' if argv[:2]==['docker','create'] else 'veth' if argv[:3]==['ip','link','add'] else None
            if marker and failures[marker]: failures[marker]=False;raise RuntimeError('injected lost '+marker+' response')
            return result
        test.run=interrupted
        for action in ('ensure','recover'):
            try:test.operate(action,configs[1] if action=='ensure' else None)
            except RuntimeError as error:
                if not str(error).startswith('injected lost'):raise
                assert test.read()['phase']=='recovery_required'
                report['checks'].append(str(error));save()
            else:raise RuntimeError('lost response injection was not exercised')
        r=test.operate('recover');assert r['phase']=='active';original=r['container_id'];ssh_ready(configs[1])
        from dnlab_multinode.services import jumphost
        jumphost.PATHS = dataclasses.replace(jumphost.PATHS, jumphost_journal_dir=str(root/'journal'),management_journal_dir=str(root/'management-journal'))
        class LocalTransport:
            def run_input(self, command, payload, timeout):
                result = subprocess.run(shlex.split(command), input=payload, text=True, capture_output=True, timeout=timeout)
                if result.returncode: raise RuntimeError('local stdin guard transport failed: '+result.stderr[-1500:])
                return result.stdout
        view = jumphost._guard(LocalTransport(), test.lab, 'read')
        assert view['container_id'] == original and view['config']['generation'] == configs[1]['generation']
        jumphost.preflight_jumphost_cleanup(test.lab, LocalTransport(), configs[1]['name'], configs[1]['generation'])
        report['checks'].append('actual standalone worker over bounded stdin request; coordinator generation verified')
        assert test.operate('ensure',configs[1])['container_id']==original
        assert names(control.lab)!=names(test.lab)
        for worker in workers:
            record=worker.operate('read')
            with worker.namespace(record) as fd:
                execute(['nsenter','--net=/proc/self/fd/'+str(fd),'ping','-I','eth1','-c','1','-W','2','198.19.231.1'],pass_fds=(fd,))
        assert control_signature(control)==before
        report['checks'].extend(['same generation on replay/recovery','distinct names for common-prefix labs',
                                 'same management CIDR/IP in distinct lab VRFs','SSH banners on exact loopback bindings','management ICMP both labs','control identities unchanged'])
        if attachment_gate:
            attachment_gate(dict(root=root, configs=configs, workers=workers, report=report,
                management_workers=management_workers, network_guards=network_guards, networks=networks,
                intent=intent, save=save, transport=LocalTransport()))
            save()
        if service_gate:
            service_gate(root, configs, workers, report)
            save()
        # Hold the namespace to exercise index-bound veth removal after PID1 exit.
        descriptors.append(os.open('/proc/'+str(test.container(r)['State']['Pid'])+'/ns/net',os.O_RDONLY))
        test.operate('preflight-delete', {'container':configs[1]['name']})
        assert test.operate('delete')['phase']=='cleaned'
        assert test.operate('delete')['phase']=='cleaned'
        assert control_signature(control)==before
        assert test.operate('verify-cleaned', {'container':configs[1]['name']})['phase']=='cleaned'
        report['checks'].append('shutdown then index-bound cleanup with pinned namespace; idempotent delete; control unchanged')
        report['status']='passed';save()
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error));save();raise
    finally:
        errors=[]
        for worker in reversed(workers):
            try:
                with worker.locked():record=worker.read()
                if record:
                    worker.operate('delete')
            except Exception as error:errors.append(str(error))
        for fd in descriptors:os.close(fd)
        for entry in reversed(networks):
            if errors: break
            try:
                if entry.get('management_lab'):
                    guard=network_guards[entry['management_lab']]
                    guard.operate('preflight-cleanup');guard.operate('cleanup');guard.operate('verify-cleaned')
                    continue
                value=docker.request('GET','/networks/'+entry['payload']['Name'],missing_ok=True)
                if value:
                    if value['Id']!=entry['id'] or value.get('Labels',{}).get('io.dnlab.spike')!=lab_prefix or value.get('Containers'):
                        raise RuntimeError('network cleanup ownership/occupancy differs')
                    docker.request('DELETE','/networks/'+value['Id'])
            except Exception as error:errors.append(str(error))
        for management in reversed(management_workers):
            if errors: break
            try:
                view=management.operate('read')
                if view['record']:
                    management.operate('cleanup');management.operate('verify-cleaned')
            except Exception as error:errors.append(str(error))
        for entry in reversed(infra):
            if errors: break
            try:delete_fixture_interface(linux,entry)
            except Exception as error:errors.append(str(error))
        try:
            assert json.loads(STATE.read_text())==baseline
            assert hashlib.sha256(PLUGIN.read_bytes()).hexdigest()==plugin_sha256
            for cfg in locals().get('configs',[]):
                assert docker.inspect(cfg['name']) is None and linux.link(names(cfg['lab'])) is None
            for entry in networks:assert docker.request('GET','/networks/'+entry['payload']['Name'],missing_ok=True) is None
            for entry in infra:assert linux.link(entry['name']) is None
            for management in management_workers:
                management.operate('verify-cleaned')
                for name in management.desired(): assert linux.link(name) is None
            assert linux.link(locals().get('ext_bridge','drsp-nonexistent')) is None
        except Exception as error:errors.append('absence/baseline verification: '+str(error))
        report['cleanup']={'verified':not errors,'errors':errors};save()
        if errors:raise RuntimeError('fixture cleanup incomplete: '+repr(errors))
    return root


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--plugin-sha256',required=True);p.add_argument('--output',required=True)
    args=p.parse_args();print(run(args.image,args.plugin_sha256,args.output))
