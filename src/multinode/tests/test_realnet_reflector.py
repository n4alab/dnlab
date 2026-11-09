import copy
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

import pytest

from dnlab_multinode.services import realnet
from dnlab_multinode.services.realnet_reflector import CONFIG,CREATOR,ROLE,QualificationStore,ReflectorError,ReflectorGuard


class ReflectorSSH:
    """Structured Docker model; track destructive commands and config writes."""
    def __init__(self,configuration,*,existing=True):
        self.commands=[];self.mutations=[];self.uploads=[];self.qualifications={}
        self.image={'Id':'sha256:'+'a'*64,'Config':{'Entrypoint':['/entrypoint.sh'],'Cmd':None}}
        self.network={'Id':'b'*64,'Name':'dnlab-realnet-bgp','Driver':'macvlan',
                      'Options':{'parent':'br-host','macvlan_mode':'bridge'},'IPAM':{'Config':[{'Subnet':'10.0.0.0/24'}]}}
        self.configuration=configuration;self.running=configuration;self.ready=True
        self.container=self.make_container('c'*64,{}) if existing else None

    def make_container(self,identity,labels):
        return {'Id':identity,'Name':'/dnlab-realnet-rr','Image':self.image['Id'],'State':{'Running':True},
                'Config':{**copy.deepcopy(self.image['Config']),'Labels':labels},
                'HostConfig':{'Privileged':True,'CapAdd':['NET_ADMIN'],'NetworkMode':self.network['Name']},
                'NetworkSettings':{'Networks':{self.network['Name']:{'NetworkID':self.network['Id'],'IPAddress':'10.0.0.10'}}}}

    def managed(self):
        guard=ReflectorGuard(self);expected=guard.expected(self.image,self.network,'10.0.0.10',self.configuration)
        self.container['Config']['Labels']={ROLE:'route-reflector-v1',CONFIG:guard.fingerprint(expected),CREATOR:'d'*32}
        return self

    def run_no_check(self,command):
        self.commands.append(command)
        args=shlex.split(command)
        if args[:3]==['docker','image','inspect']:return 0,'',''
        if args[:3]==['docker','network','inspect']:return 0,'macvlan 10.0.0.0/24',''
        if args[-1]=='show bgp vrfs json':
            return (0,json.dumps({'vrfs':{'default':{'routerId':'10.0.0.10'}}}), '') if self.ready else (1,'','not ready')
        raise AssertionError(command)

    def run(self,command,check=True):
        self.commands.append(command);args=shlex.split(command)
        if args[:3]==['docker','ps','-aq']:return self.container['Id'] if self.container else ''
        if args[:2]==['docker','inspect']:return json.dumps([self.container])
        if args[:3]==['docker','image','inspect']:return json.dumps([self.image])
        if args[:3]==['docker','network','inspect']:return json.dumps([self.network])
        if args[:2]==['docker','run']:
            assert self.container is None
            labels={args[i+1].split('=',1)[0]:args[i+1].split('=',1)[1] for i,value in enumerate(args) if value=='--label'}
            self.container=self.make_container('e'*64,labels);self.configuration='';self.running=''
            self.mutations.append(('create',self.container['Id']));return self.container['Id']
        if args[:2]==['docker','cp']:
            self.configuration=self.uploads[-1][0];self.mutations.append(('copy',args[-1]));return ''
        if args[:2]==['docker','exec']:
            if args[3]=='sha256sum':return hashlib.sha256(self.configuration.encode()).hexdigest()+'  /etc/frr/frr.conf'
            if args[-1]=='show running-config':return self.running
            if args[3]=='sh':self.running=self.configuration;self.mutations.append(('configure',args[2]));return ''
        if args[0]=='mktemp':return '/tmp/dnlab-rr-config-0123456789'
        if args[0]=='rm':return ''
        if args[0]=='python3':
            identity=args[4]
            if len(args)==6:self.qualifications[identity]=json.loads(args[5])
            return json.dumps(self.qualifications.get(identity))
        raise AssertionError(command)

    def upload_text(self,content,path):self.uploads.append((content,path))


def configured_topology(topo_factory):
    topo=topo_factory(num_workers=0);topo.realnet_infra.rr_ip='10.0.0.10'
    topo.realnet_infra.host_net='10.0.0.0/24';topo.realnet_infra.wan_iface='br-host'
    return topo


@pytest.fixture
def fixture(topo_factory):
    topo=configured_topology(topo_factory);client=ReflectorSSH(realnet._rr_frr_config(topo.realnet_infra)).managed()
    return topo,client


def test_two_labs_reuse_same_reflector_without_restart_or_config_writes(fixture):
    topo,client=fixture;identity=client.container['Id']
    realnet.deploy_route_reflector(topo,client);topo.name='another-lab';realnet.deploy_route_reflector(topo,client)
    assert client.container['Id']==identity and not client.mutations and not client.uploads


@pytest.mark.parametrize('capability',['NET_ADMIN','CAP_NET_ADMIN'])
def test_docker_capability_spellings_preserve_compatible_reflector(fixture,capability):
    topo,client=fixture;identity=client.container['Id']
    client.container['HostConfig']['CapAdd']=[capability]
    realnet.deploy_route_reflector(topo,client)
    assert client.container['Id']==identity and not client.mutations and not client.uploads


@pytest.mark.parametrize('change',['image','parent','driver','network_id','ip','privilege','entrypoint','role','label_config','creator','stopped','not_ready','file','running'])
def test_incompatible_reflector_is_rejected_without_mutation(fixture,change):
    topo,client=fixture
    if change=='image':client.container['Image']='sha256:'+'f'*64
    if change=='parent':client.network['Options']['parent']='other-parent'
    if change=='driver':client.network['Driver']='bridge'
    if change=='network_id':client.container['NetworkSettings']['Networks']['dnlab-realnet-bgp']['NetworkID']='f'*64
    if change=='ip':client.container['NetworkSettings']['Networks']['dnlab-realnet-bgp']['IPAddress']='10.0.0.11'
    if change=='privilege':client.container['HostConfig']['Privileged']=False
    if change=='entrypoint':client.container['Config']['Entrypoint']=['other']
    if change=='role':client.container['Config']['Labels'][ROLE]='foreign'
    if change=='label_config':client.container['Config']['Labels'][CONFIG]='foreign'
    if change=='creator':client.container['Config']['Labels'][CREATOR]='invalid'
    if change=='stopped':client.container['State']['Running']=False
    if change=='not_ready':client.ready=False
    if change=='file':client.configuration+='! modified\n'
    if change=='running':client.running=client.running.replace('router bgp 64512','router bgp 65001')
    with pytest.raises(ReflectorError):realnet.deploy_route_reflector(topo,client)
    assert not client.mutations and not client.uploads


def test_legacy_requires_explicit_qualification_pinned_to_container_identity(fixture):
    topo,client=fixture;client.container['Config']['Labels']={};identity=client.container['Id']
    with pytest.raises(ReflectorError,match='legacy'):realnet.deploy_route_reflector(topo,client)
    result=realnet.qualify_route_reflector(topo,client)
    assert result['container_id']==identity and identity in client.qualifications
    realnet.deploy_route_reflector(topo,client)
    assert not client.mutations and not client.uploads
    client.container['Id']='f'*64
    with pytest.raises(ReflectorError,match='legacy'):realnet.deploy_route_reflector(topo,client)


def test_qualification_does_not_override_foreign_labels_or_incompatible_config(fixture):
    topo,client=fixture;client.container['Config']['Labels'][ROLE]='foreign'
    with pytest.raises(ReflectorError,match='ownership'):realnet.qualify_route_reflector(topo,client)
    assert not client.qualifications and not client.mutations


def test_absent_reflector_is_created_once_and_configured_only_by_its_id(topo_factory):
    topo=configured_topology(topo_factory);configuration=realnet._rr_frr_config(topo.realnet_infra)
    client=ReflectorSSH(configuration,existing=False)
    realnet.deploy_route_reflector(topo,client);identity=client.container['Id'];mutations=list(client.mutations)
    realnet.deploy_route_reflector(topo,client)
    assert client.mutations==mutations and identity=='e'*64
    assert [action[0] for action in mutations]==['create','copy','configure']
    assert client.container['Config']['Labels'][ROLE]=='route-reflector-v1'


def test_frr_password_is_uploaded_without_embedding_it_in_shell_commands(topo_factory):
    topo=configured_topology(topo_factory);topo.realnet_infra.rr_password='private-test-password'
    configuration=realnet._rr_frr_config(topo.realnet_infra);client=ReflectorSSH(configuration,existing=False)
    realnet.deploy_route_reflector(topo,client)
    assert 'private-test-password' in client.uploads[0][0]
    assert all('private-test-password' not in command for command in client.commands)


class LocalRunner:
    def run(self,command):return subprocess.run(['/bin/sh','-c',command],check=True,text=True,capture_output=True,timeout=5).stdout


def test_qualification_store_is_atomic_private_and_refuses_changed_proof(tmp_path):
    store=QualificationStore(LocalRunner(),str(tmp_path/'proof'));identity='a'*64;record={'container_id':identity,'fingerprint':'f'*64}
    assert store.read(identity) is None and store.save(identity,record)==record and store.read(identity)==record
    assert (tmp_path/'proof').stat().st_mode&0o777==0o700
    assert (tmp_path/'proof'/('rr-'+identity+'.json')).stat().st_mode&0o777==0o600
    with pytest.raises(ReflectorError):store.save(identity,{**record,'fingerprint':'e'*64})
    assert store.read(identity)==record


@pytest.mark.parametrize('change',['symlink','permissions'])
def test_qualification_store_refuses_untrusted_record(tmp_path,change):
    directory=tmp_path/'proof';directory.mkdir(mode=0o700);identity='a'*64;path=directory/('rr-'+identity+'.json')
    if change=='symlink':path.symlink_to(tmp_path/'other')
    else:path.write_text('{}');path.chmod(0o644)
    with pytest.raises(ReflectorError):QualificationStore(LocalRunner(),str(directory)).read(identity)


def test_existing_reflector_cannot_be_configured_as_a_new_resource(fixture):
    _,client=fixture;guard=ReflectorGuard(client)
    with pytest.raises(ReflectorError,match='newly created'):guard.configure_new(client.container['Id'],client.configuration)
    assert not client.mutations and not client.uploads


def test_concurrent_creation_never_overwrites_another_operation(topo_factory):
    topo=configured_topology(topo_factory)
    class RaceSSH(ReflectorSSH):
        first=True
        def run(self,command,check=True):
            if self.first and shlex.split(command)[:3]==['docker','ps','-aq']:
                self.first=False;return ''
            return super().run(command,check)
    client=RaceSSH(realnet._rr_frr_config(topo.realnet_infra)).managed();identity=client.container['Id']
    with pytest.raises(ReflectorError):realnet.deploy_route_reflector(topo,client)
    assert client.container['Id']==identity and not client.mutations and not client.uploads
    realnet.deploy_route_reflector(topo,client)
    assert not client.mutations


def test_explicit_qualification_cli_does_not_require_lab_deployment(monkeypatch,fixture):
    from click.testing import CliRunner
    from dnlab_multinode.cli import main
    from dnlab_multinode.services import config,ssh
    topo,_=fixture;calls=[]
    class Connection:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr(config,'parse_topology',lambda *a,**k:topo)
    monkeypatch.setattr(ssh,'SSHClient',Connection)
    monkeypatch.setattr(realnet,'qualify_route_reflector',lambda t,c:calls.append(t.name) or {'container_id':'a'*64})
    result=CliRunner().invoke(main,['realnet-infra','qualify-reflector','--topo','lab.yml'])
    assert result.exit_code==0 and calls==[topo.name]
