#!/usr/bin/env python3
"""Dedicated RealNet RR ownership/reuse fixture; never touches the shared RR."""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_multinode.services.realnet import _rr_frr_config
from dnlab_multinode.services.realnet_reflector import CONFIG,CREATOR,ROLE,QualificationStore,ReflectorError,ReflectorGuard
from dnlab_runtime.backend import Docker,Linux
from dnlab_runtime.vxlan import link_signature


class LocalSSH:
    def __init__(self):self.commands=[]
    def run_no_check(self,command):
        self.commands.append(shlex.split(command))
        result=subprocess.run(['/bin/sh','-c',command],text=True,capture_output=True,timeout=30)
        return result.returncode,result.stdout,result.stderr
    def run(self,command):
        rc,out,_=self.run_no_check(command)
        if rc:raise RuntimeError('fixture command failed')
        return out.strip()
    def upload_text(self,content,path):Path(path).write_text(content)


def cleanup_container(api,original):
    """Kill only the recorded fixture identity, then remove without force."""
    identity=original['Id']
    if not re.fullmatch('[0-9a-f]{64}',identity):raise RuntimeError('invalid fixture container identity')
    def owned(value):
        if (value['Id']!=identity or value['Name']!=original['Name'] or value['Image']!=original['Image']
                or value['Config']['Labels']!=original['Config']['Labels']):
            raise RuntimeError('fixture container ownership differs')
    observed=api.inspect(identity)
    if observed is None:return
    owned(observed)
    if observed['State']['Running']:
        api.signal(identity,'SIGKILL')
        api.request('POST',f'/containers/{identity}/wait?condition=not-running',missing_ok=True)
    observed=api.inspect(identity)
    if observed is None:return
    owned(observed)
    if observed['State']['Running']:raise RuntimeError('fixture container did not stop')
    api.remove(identity)
    if api.inspect(identity) is not None:raise RuntimeError('fixture container removal not verified')


def run(reference):
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-rr-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8];parent='drsp'+token+'r';network_name='drsp-rr-net-'+token
    master=LocalSSH();linux=Linux();api=Docker();created=[];network=None;parent_identity=None
    report={'scope':'dedicated-local-RealNet-reflector-guard','status':'running','global_shared_RR_touched':False,
            'BGP_peering_qualified':False,'SSH_qualified':False}
    def command(*args):return master.run(shlex.join(args))
    def assert_read_only(commands):
        for argv in commands:
            assert argv[:3] in (['docker','ps','-aq'],['docker','image','inspect'],['docker','network','inspect']) or argv[:2]==['docker','inspect'] or argv[:2]==['python3','-c'] or (argv[:2]==['docker','exec'] and (argv[3]=='sha256sum' or argv[3]=='vtysh' and argv[-1].startswith('show '))),argv[:4]
    try:
        assert linux.link(parent) is None
        command('ip','link','add',parent,'type','dummy')
        command('ip','link','set','dev',parent,'alias','dnlab-runtime:fixture-rr-'+token)
        command('ip','link','set','dev',parent,'up');parent_identity=link_signature(linux.link(parent))
        network_id=command('docker','network','create','--driver','macvlan','-o','parent='+parent,'-o','macvlan_mode=bridge','--subnet','198.18.208.0/24',network_name)
        network={'id':network_id,'name':network_name}
        store=QualificationStore(master,str(root/'qualifications'))
        guard=ReflectorGuard(master,name='drsp-rr-managed-'+token,qualifications=store)
        image=guard.image(reference);report['image']=image['Id']
        network_info=guard.network(network_name,'198.18.208.0/24',parent)
        cfg=SimpleNamespace(rr_as=64512,rr_ip='198.18.208.10',host_net='198.18.208.0/24',rr_password='')
        configuration=_rr_frr_config(cfg);expected=guard.expected(image,network_info,cfg.rr_ip,configuration)
        identity=guard.create(image,expected);created.append(api.inspect(identity))
        guard.configure_new(identity,configuration);guard.wait_ready(image,expected)
        before=api.inspect(identity);count=len(master.commands)
        for _ in range(2):guard.verify(guard.inspect(),image,expected)
        assert_read_only(master.commands[count:]);after=api.inspect(identity)
        assert before['Id']==after['Id'] and before['State']['StartedAt']==after['State']['StartedAt']
        report['reuse_preserves_id_and_start_time']=True
        count=len(master.commands)
        try:guard.verify(guard.inspect(),image,{**expected,'config_sha256':'f'*64})
        except ReflectorError:pass
        else:raise AssertionError('incompatible configuration accepted')
        assert_read_only(master.commands[count:]);guard.verify(guard.inspect(),image,expected)
        report['incompatible_configuration_rejected_without_mutation']=True
        legacy=ReflectorGuard(master,name='drsp-rr-legacy-'+token,qualifications=store)
        cfg.rr_ip='198.18.208.11';legacy_configuration=_rr_frr_config(cfg)
        legacy_expected=legacy.expected(image,network_info,cfg.rr_ip,legacy_configuration)
        legacy_id=command('docker','run','-d','--name',legacy.name,'--hostname','realnet-rr','--privileged','--cap-add','NET_ADMIN',
                          '--network',network_name,'--ip',cfg.rr_ip,'--label','io.dnlab.spike='+token,image['Id'])
        created.append(api.inspect(legacy_id))
        config_path=root/'legacy.conf';config_path.write_text(legacy_configuration);config_path.chmod(0o600)
        command('docker','cp',str(config_path),legacy_id+':/etc/frr/frr.conf')
        command('docker','exec',legacy_id,'sh','-ec',"sed -i 's/^bgpd=.*/bgpd=yes/' /etc/frr/daemons; chown frr:frr /etc/frr/frr.conf; /usr/lib/frr/frrinit.sh restart; vtysh -b")
        count=len(master.commands)
        try:legacy.verify(legacy.inspect(),image,legacy_expected)
        except ReflectorError as error:assert 'legacy' in str(error)
        else:raise AssertionError('legacy implicitly adopted')
        qualified=legacy.verify(legacy.inspect(),image,legacy_expected,qualify=True)
        legacy.verify(legacy.inspect(),image,legacy_expected);assert_read_only(master.commands[count:])
        assert qualified['container_id']==legacy_id and store.read(legacy_id)['container_id']==legacy_id
        report['legacy_qualified_without_restart']=True
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        try:
            for original in reversed(created):
                cleanup_container(api,original)
            if network:
                value=json.loads(command('docker','network','inspect',network['id']))[0]
                assert value['Name']==network['name'] and value['Options']['parent']==parent and not value.get('Containers')
                command('docker','network','rm',network['id'])
            if parent_identity:
                assert link_signature(linux.link(parent))==parent_identity
                command('ip','link','delete','dev',parent);assert linux.link(parent) is None
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            report['containers']=[{'id':value['Id'],'name':value['Name']} for value in created]
            (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps({'report':str(root/'report.json'),'status':report.get('status'),'error':report.get('error'),'cleanup_verified':report.get('cleanup_verified')}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');parser.add_argument('--image',required=True);args=parser.parse_args()
    if not args.execute:print(json.dumps({'mutations_performed':False,'creates':'dedicated dummy, macvlan network, managed and legacy RR fixtures'}))
    elif os.geteuid()!=0:raise RuntimeError('gate requires root')
    else:run(args.image)
