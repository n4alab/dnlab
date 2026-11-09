"""Stateful Docker births and real probe journal/endpoint state machine."""
from copy import deepcopy
import json
import os
from urllib.parse import urlparse,parse_qs,unquote
import pytest
from dnlab_multinode.services.management_probe_host import Worker,INIT
from dnlab_multinode.services.jumphost_host import JumphostError,signature
from tests.test_jumphost_host import World as Links,config
from tests.test_management_probe_identity import configured
from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.mgmt_network import _expected_network
from dnlab_multinode.services.management_services import compile_services
from tests.test_management_services import external


class Docker:
    def __init__(self,image):
        self.image={'Id':image,'Config':{'Env':['PATH=/usr/bin'],'Labels':{}}};self.values={};self.calls=[];self.lost=None;self.creates=0
        self.execs={};self.exec_creates=0;self.exec_starts=0;self.exec_lost=None;self.on_exec_start=lambda row:None;self.on_exec_inspect=lambda row:None
    def call(self,method,path,payload=None,**kwargs):
        self.calls.append((method,path));route=urlparse(path);parts=route.path.split('/');query=parse_qs(route.query)
        if parts[1]=='exec':
            row=self.execs.get(parts[2])
            if method=='GET':
                if row:self.on_exec_inspect(row)
                return deepcopy(row)
            assert row is not None and method=='POST' and parts[-1]=='start'
            self.exec_starts+=1;row.update(Running=True,Pid=100,ExitCode=None);self.on_exec_start(row)
            if self.exec_lost=='start':raise JumphostError('lost packet start reply')
            return {}
        if method=='POST' and parts[-1]=='exec':
            self.exec_creates+=1
            if self.exec_lost=='before-create':raise JumphostError('packet create unresolved')
            identity='e'+format(self.exec_creates,'063x');cmd=payload['Cmd']
            self.execs[identity]={'ID':identity,'ContainerID':parts[2],'Running':False,'Pid':0,'ExitCode':None,
                'ProcessConfig':{'tty':False,'entrypoint':cmd[0],'arguments':cmd[1:],'privileged':False,'user':'0'},
                'OpenStdin':False,'OpenStdout':False,'OpenStderr':False}
            self.values[parts[2]].setdefault('ExecIDs',[]).append(identity)
            if self.exec_lost=='create':raise JumphostError('lost packet create reply')
            return {'Id':identity}
        if method=='GET' and parts[1]=='images':return deepcopy(self.image)
        if method=='GET' and route.path=='/containers/json':
            nonce=json.loads(query['filters'][0])['label'][0].split('=',1)[1]
            return [{'Id':cid} for cid,row in self.values.items() if row['Config']['Labels'].get('org.dnlab.management-probe.nonce')==nonce]
        if method=='POST' and route.path=='/containers/create':
            self.creates+=1
            if self.lost=='before-create':raise JumphostError('uncertain transport')
            cid=str(self.creates)*64;host=deepcopy(payload['HostConfig'])
            host.update(Privileged=False,PortBindings={},PidMode='',IpcMode='private');host.setdefault('CapAdd',None);host.setdefault('Binds',[])
            host['RestartPolicy']['MaximumRetryCount']=0
            cfg={key:deepcopy(payload[key]) for key in ('Image','Entrypoint','Cmd','User','Labels','Healthcheck')};cfg['Env']=self.image['Config']['Env']
            self.values[cid]={'Id':cid,'Name':'/'+query['name'][0],'Image':self.image['Id'],'Config':cfg,'HostConfig':host,
                'Mounts':[{'Type':'bind','Source':v.split(':')[0],'Destination':v.split(':')[1],'RW':v.split(':')[2]=='rw'} for v in host['Binds']],
                'ExecIDs':[],'NetworkSettings':{'Networks':{'none':{}}},'State':{'Running':False,'Pid':0,'StartedAt':'zero'}}
            if self.lost=='create':raise JumphostError('lost create reply')
            return {'Id':cid}
        identity=parts[2] if len(parts)>2 else ''
        row=next((v for k,v in self.values.items() if identity in (k,v['Name'][1:])),None)
        if method=='GET':return deepcopy(row)
        if row is None:raise AssertionError((method,path))
        if method=='POST' and parts[-1]=='start':
            row['State']={'Running':True,'Pid':100,'StartedAt':'first'}
            if self.lost=='start':raise JumphostError('lost start reply')
            return {}
        if method=='POST' and parts[-1]=='kill':row['State']['Running']=False;return {}
        if method=='DELETE':del self.values[row['Id']];return {}
        raise AssertionError((method,path))


@pytest.fixture
def fixture(topo_factory,tmp_path):
    topo,model=resolve(configured(topo_factory),prepare_probes=True);cfg=_expected_network(topo,'master')
    services=compile_services(model,external(topo))
    request={'lab':topo.name,'segment':'default','host':'master','request_id':'1'*32,'operation_id':'2'*32,
        'image':'sha256:'+'a'*64,'identity':model['probes']['default'],
        'attachment':services['jumphost']['attachments']['default']['config'],'management_intent':cfg,
        'management_generation':'3'*32,'network_id':'4'*64,'network_nonce':'5'*32}
    links=Links(config());bridge=links.host[1];bridge['ifname']=cfg['bridge']
    proof={'network':{'Id':request['network_id']},'origin':{'generation':request['management_generation'],'network_nonce':request['network_nonce']}}
    docker=Docker(request['image']);namespace=tmp_path/'namespace';namespace.write_text('namespace')
    worker=Worker(request,directory=tmp_path/'journal',management_directory=tmp_path/'management',docker=docker,
        process_status=lambda pid:'SigCgt:\t0000000000004000\n',run=lambda *args,**kwargs:None,host_context=lambda:{'boot_id':'boot','device':1,'inode':2},open_ns=lambda pid:os.open(namespace,os.O_RDONLY))
    worker.management_network=lambda c:deepcopy(proof)
    fault=[None]
    def run(argv,**kwargs):
        peer=argv[0]=='nsenter';selected=argv[2:] if peer else argv
        pool=links.peer if peer else links.host
        if selected[:4]==['ip','-j','-d','link']:return json.dumps(pool)
        if selected[:3]==['ip','link','add']:
            p=selected.index('peer');other=selected[p:]
            links.host.append(links.link(selected[3],20,address=selected[5],link_index=21,flags=[]))
            links.peer.append(links.link('probe0',21,address=other[4],link_index=20,flags=[]))
            if fault[0]=='create-link':fault[0]=None;raise JumphostError('lost link reply')
            return ''
        if selected[:2]==['python3','-c']:
            payload=json.loads(selected[-1]);value=next(v for v in pool if v['ifindex']==payload['link']['ifindex'])
            assert signature(value)==payload['link']
            if payload['operation']=='alias':
                value['ifalias']=payload['value']
                if fault[0]==('peer-alias' if peer else 'host-alias'):
                    fault[0]=None;raise JumphostError('lost alias reply')
            if payload['operation']=='master':value['master']=payload['value']['ifindex']
            if payload['operation']=='up':value['flags']=['UP']
            return '{}'
        raise AssertionError(argv)
    def delete(expected,scope):
        value=next(v for v in links.host if v['ifname']==expected['ifname']);assert signature(value)==expected
        links.host.remove(value);links.peer=[]
        if fault[0]=='delete-link':fault[0]=None;raise JumphostError('lost delete reply')
    worker.run=run;worker.delete_link=delete
    return worker,docker,links,proof,fault


def test_birth_endpoint_and_cleanup_are_idempotent_without_topology_nodes(fixture):
    w,d,links,proof,fault=fixture
    assert w.operate('preflight')['phase']=='preflight' and not w.directory.exists()
    first=w.operate('ensure');assert first['phase']=='active' and d.creates==1
    assert w.operate('ensure')['container_id']==first['container_id'] and d.creates==1
    result=w.operate('cleanup');assert result['phase']=='cleaned' and result['cleanup_verified'] is True
    assert w.operate('verify-cleaned')==result and w.operate('ensure')==result
    assert not d.values and not links.peer and not any(v['ifname']==w.interface for v in links.host)


@pytest.mark.parametrize('phase',['create','start','create-link','host-alias','peer-alias','delete-link'])
def test_lost_replies_recover_original_birth_and_cleanup(fixture,phase):
    w,d,links,proof,fault=fixture
    if phase in ('create','start'):d.lost=phase
    elif phase in ('create-link','host-alias','peer-alias'):fault[0]=phase
    if phase!='delete-link':
        with pytest.raises(JumphostError):w.operate('ensure')
        nonce=w.read()['nonce'];d.lost=None
        assert w.operate('ensure')['nonce']==nonce and d.creates==1
    else:
        w.operate('ensure');fault[0]=phase
        with pytest.raises(JumphostError):w.operate('cleanup')
        assert w.read()['phase']=='cleanup_pending'
    assert w.operate('cleanup')['phase']=='cleaned' and not d.values


def test_uncertain_absent_create_never_recreates_or_claims_cleaned(fixture):
    w,d,links,proof,fault=fixture;d.lost='before-create'
    with pytest.raises(JumphostError):w.operate('ensure')
    d.lost=None
    with pytest.raises(JumphostError,match='no new create'):w.operate('ensure')
    with pytest.raises(JumphostError,match='outcome unknown'):w.operate('cleanup')
    assert d.creates==1 and w.read()['phase']=='cleanup_pending'


@pytest.mark.parametrize('replacement',['container','endpoint','network'])
def test_replaced_resources_are_preserved_before_cleanup(fixture,replacement):
    w,d,links,proof,fault=fixture;record=w.operate('ensure')
    if replacement=='container':
        value=d.values.pop(record['container_id']);value['Id']='f'*64;d.values[value['Id']]=value
    if replacement=='endpoint':next(v for v in links.host if v['ifname']==w.interface)['ifindex']=99
    if replacement=='network':proof['network']['Id']='f'*64
    before=deepcopy((d.values,links.host,links.peer));calls=len(d.calls)
    with pytest.raises(JumphostError):w.operate('cleanup')
    assert (d.values,links.host,links.peer)==before
    assert all(method=='GET' for method,path in d.calls[calls:])


def test_stdin_program_is_standalone_without_allocating_resources():
    import subprocess,sys
    from dnlab_multinode.services.management_probe_runtime import program
    source=program();assert len(source)>131072
    marker="if __name__=='__main__':main()"
    source=source.rsplit(marker,1)[0]+"print('standalone-probe-imports-ok')"
    result=subprocess.run([sys.executable,'-c','import sys;exec(sys.stdin.read())'],input=source,text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='standalone-probe-imports-ok'


def test_late_init_handler_is_observed_before_endpoint_allocation(fixture):
    w,d,links,proof,fault=fixture;calls=[]
    def status(pid):
        assert not any(v['ifname']==w.interface for v in links.host)
        calls.append(pid)
        return 'SigCgt:\t'+('0' if len(calls)==1 else '4000')+'\n'
    w.process_status=status
    assert w.operate('ensure')['phase']=='active' and len(calls)==2
    w.operate('cleanup')


@pytest.mark.parametrize('field',['CapAdd','Binds','PortBindings','ReadonlyRootfs'])
def test_foreign_container_configuration_refused_before_cleanup(fixture,field):
    w,d,links,proof,fault=fixture;record=w.operate('ensure')
    values={'CapAdd':['NET_ADMIN'],'Binds':['/tmp:/tmp'],'PortBindings':{'22/tcp':[]},'ReadonlyRootfs':False}
    d.values[record['container_id']]['HostConfig'][field]=values[field]
    before=deepcopy((d.values,links.host,links.peer))
    with pytest.raises(JumphostError):w.operate('cleanup')
    assert (d.values,links.host,links.peer)==before


@pytest.mark.parametrize('phase',['create-link','host-alias','peer-alias'])
def test_cleanup_qualifies_original_pair_with_absent_or_partial_aliases(fixture,phase):
    w,d,links,proof,fault=fixture;fault[0]=phase
    with pytest.raises(JumphostError):w.operate('ensure')
    assert w.read()['qualifying'] is True
    host=next(v for v in links.host if v['ifname']==w.interface)
    assert host.get('master') is None
    assert w.operate('cleanup')['phase']=='cleaned'
    assert not d.values and not links.peer


@pytest.mark.parametrize('side',['host','peer'])
@pytest.mark.parametrize('change',['foreign-alias','mac','ifindex','peer-index','kind'])
def test_initial_qualification_preserves_foreign_or_replaced_pair(fixture,side,change):
    w,d,links,proof,fault=fixture;fault[0]='create-link'
    with pytest.raises(JumphostError):w.operate('ensure')
    value=next(v for v in (links.host if side=='host' else links.peer) if v['ifname']==(w.interface if side=='host' else 'probe0'))
    if change=='foreign-alias':value['ifalias']='foreign'
    if change=='mac':value['address']='02:ff:ff:ff:ff:ff'
    if change=='ifindex':value['ifindex']=99
    if change=='peer-index':value['link_index']=99
    if change=='kind':value['linkinfo']['info_kind']='dummy'
    before=deepcopy((d.values,links.host,links.peer))
    for action in ('ensure','cleanup'):
        with pytest.raises(JumphostError):w.operate(action)
        assert (d.values,links.host,links.peer)==before
    assert d.creates==1


@pytest.mark.parametrize('side',['host','peer'])
def test_completed_qualification_never_accepts_missing_alias(fixture,side):
    w,d,links,proof,fault=fixture;w.operate('ensure')
    value=next(v for v in (links.host if side=='host' else links.peer) if v['ifname']==(w.interface if side=='host' else 'probe0'))
    value.pop('ifalias')
    before=deepcopy((d.values,links.host,links.peer))
    for action in ('ensure','cleanup'):
        with pytest.raises(JumphostError):w.operate(action)
        assert (d.values,links.host,links.peer)==before


@pytest.mark.parametrize('boundary',['host_alias','peer_alias','qualification_commit'])
def test_crash_after_alias_verification_recovers_without_new_pair(fixture,boundary):
    w,d,links,proof,fault=fixture;save=w.save;failed=[]
    def interrupted(record):
        if not failed and ((boundary=='qualification_commit' and record.get('qualifying') is False)
                or (record.get('step')==boundary and record.get('host')
                    and record['host']['ifalias']==record['alias']
                    and (boundary!='peer_alias' or record['peer']['ifalias']==record['alias']))):
            failed.append(True);raise JumphostError('checkpoint failed')
        save(record)
    w.save=interrupted
    with pytest.raises(JumphostError,match='checkpoint failed'):w.operate('ensure')
    host=next(v for v in links.host if v['ifname']==w.interface)
    assert host.get('master') is None
    original=host['ifindex'];w.save=save
    assert w.operate('ensure')['phase']=='active'
    assert next(v for v in links.host if v['ifname']==w.interface)['ifindex']==original and d.creates==1
    assert w.operate('cleanup')['phase']=='cleaned'
