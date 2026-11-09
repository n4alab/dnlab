"""Original GUI client configuration, framing and cleanup proof checks."""
import ast
from copy import deepcopy
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import pytest

TOOLS=Path(__file__).resolve().parents[1]/'tools'
sys.path[:0]=[str(TOOLS),str(TOOLS.parents[1]/'multinode')]
import management_gui_forward as module
from dnlab_multinode.services import management_dns_probe as wire


def test_pending_requires_explicit_cleanup_and_preserves_bad_state(tmp_path):
    assert module.pending(tmp_path) is False
    (tmp_path/'gui-client').mkdir()
    assert module.pending(tmp_path) is True
    path=tmp_path/'gui-forwarding.json';path.write_text('{bad')
    assert module.pending(tmp_path) is True
    path.write_text(json.dumps({'cleanup_verified':True}))
    assert module.pending(tmp_path) is False


@pytest.fixture
def config(monkeypatch):
    expected={'Image':'sha256:gui','Entrypoint':['python','/run/client.py'],'Cmd':[],'User':'0:0',
              'Labels':{'birth':'original'},'Env':['X=overridden','Y=extra'],
              'HostConfig':{'NetworkMode':'host','CapDrop':['ALL'],'ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'},'Binds':['/own/a:/a:ro','/own/b:/b:rw']}}
    current={'Image':expected['Image'],'Config':{**deepcopy(expected),'Env':['BASE=original','X=overridden','Y=extra']},
             'HostConfig':{**deepcopy(expected['HostConfig']),'Privileged':False,'IpcMode':'private','PidMode':'','PortBindings':None,'CapAdd':None}}
    monkeypatch.setattr(module.NosFixture,'bind_response',lambda self,value:current)
    owner=object.__new__(module.GuiFixture);owner.spec={'image':expected['Image']}
    owner.backend=SimpleNamespace(docker=SimpleNamespace(request=lambda *a:{'Config':{'Env':['BASE=original','X=old']}}))
    return owner,{'effective_config':expected},current


def test_same_immutable_config_accepts_bind_order_only(config):
    owner,value,current=config;current['HostConfig']['Binds'].reverse()
    assert owner.bind_response(value) is current


@pytest.mark.parametrize('change',['image','command','user','label','env','namespace','privileged','rootfs','cap','mount','port'])
def test_foreign_or_changed_gui_client_config_is_refused(config,change):
    owner,value,current=config
    if change=='image':current['Image']='replacement'
    if change=='command':current['Config']['Cmd']=['other']
    if change=='user':current['Config']['User']='1:1'
    if change=='label':current['Config']['Labels']={}
    if change=='env':current['Config']['Env']+=['X=duplicate']
    if change=='namespace':current['HostConfig']['PidMode']='host'
    if change=='privileged':current['HostConfig']['Privileged']=True
    if change=='rootfs':current['HostConfig']['ReadonlyRootfs']=False
    if change=='cap':current['HostConfig']['CapAdd']=['NET_ADMIN']
    if change=='mount':current['HostConfig']['Binds'][0]='/foreign:/a:ro'
    if change=='port':current['HostConfig']['PortBindings']={'53/tcp':[]}
    with pytest.raises(RuntimeError,match='configuration differs'):owner.bind_response(value)


@pytest.mark.parametrize('address',['192.0.2.5','2001:db8::5'])
def test_forwarded_dns_query_validates_partial_tcp_reads_and_original_answer(address):
    parsed=ast.parse((TOOLS/'gui_forward_client.py').read_text())
    function=next(n for n in parsed.body if isinstance(n,ast.FunctionDef) and n.name=='query')
    record={'name':'fixture.invalid','address':address}
    class Stream:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,*args):pass
        def sendall(self,data):
            request=data[2:];question=request[12:];kind=1 if ':' not in address else 28
            reply=struct.pack('!HHHHHH',int.from_bytes(request[:2],'big'),0x8180,1,1,0,0)+question
            packed=ipaddress.ip_address(address).packed
            reply+=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,30,len(packed))+packed
            self.data=len(reply).to_bytes(2,'big')+reply
        def recv(self,count):
            part=self.data[:min(count,3)];self.data=self.data[len(part):];return part
    stream=Stream();namespace={'ipaddress':ipaddress,'os':os,'struct':struct,'socket':SimpleNamespace(create_connection=lambda *a,**kw:stream)}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'query','exec'),namespace)
    assert namespace['query'](12345,record,wire)['address']==address


@pytest.mark.parametrize('failure',[None,'hash','origin','manifest','missing','path-env','path-symlink','settings-path'])
def test_bootstrap_pins_package_and_loaded_modules_before_connections(tmp_path,failure):
    import hashlib
    import subprocess
    package=tmp_path/'gui'
    for directory in (package/'app',package/'app/services',package/'app/views',package/'app/views/api'):
        directory.mkdir(parents=True,exist_ok=True)
        (directory/'__init__.py').write_text('')
    (package/'app/config.py').write_text("from types import SimpleNamespace\nimport os\nsettings = SimpleNamespace(TOPOLOGIES_DIR=os.environ['TOPOLOGIES_DIR'],LOG_DIR=os.environ['DNLABGUI_LOG_DIR'])\n")
    (package/'app/services/webui_listener.py').write_text('class Listener: pass\n')
    (package/'app/services/webui_service.py').write_text('from app import config\nfrom app.services import webui_listener\nclass WebUIService: pass\n')
    expected={'app.services.'+name:hashlib.sha256((package/'app/services'/(name+'.py')).read_bytes()).hexdigest() for name in ('webui_service','webui_listener')}
    (package/'app/views/api/webui_routes.py').write_text('# inert route module for bootstrap audit\n')
    expected['app.views.api.webui_routes']=hashlib.sha256((package/'app/views/api/webui_routes.py').read_bytes()).hexdigest()
    output=tmp_path/'output';output.mkdir()
    profile={'gui_root':str(package),'gui_output':str(output),'gui_modules':expected}
    environment={**os.environ,'TOPOLOGIES_DIR':str(output/'topologies'),'DNLABGUI_LOG_DIR':str(output/'logs')}
    if failure=='path-env':environment['TOPOLOGIES_DIR']=str(tmp_path/'foreign')
    if failure=='path-symlink':(output/'logs').symlink_to(tmp_path,target_is_directory=True)
    if failure=='settings-path':
        with (package/'app/config.py').open('a') as stream:stream.write("settings.LOG_DIR='/foreign/logs'\n")
    if failure=='hash':expected['app.services.webui_service']='0'*64
    if failure=='manifest':expected.clear()
    if failure=='missing':(package/'app/__init__.py').unlink()
    script="""
import importlib.util,json,sys,types
from pathlib import Path
spec=importlib.util.spec_from_file_location('client',sys.argv[1])
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
profile=json.loads(sys.argv[2])
if sys.argv[3]=='origin':
    fake=types.ModuleType('app');fake.__file__='/foreign/app/__init__.py';fake.__path__=[profile['gui_root']+'/app'];sys.modules['app']=fake
service,audit=client.bootstrap(profile)
assert service.__name__=='WebUIService'
assert set(audit)=={'app','app.services','app.config',*profile['gui_modules']}
print(json.dumps(audit))
"""
    result=subprocess.run([sys.executable,'-c',script,str(TOOLS/'gui_forward_client.py'),json.dumps(profile),str(failure)],cwd=tmp_path,env=environment,capture_output=True,text=True,timeout=10)
    if failure:
        assert result.returncode!=0
        assert 'GUI ' in result.stderr
    else:
        assert result.returncode==0,result.stderr
        audit=json.loads(result.stdout)
        assert all(row['path'].startswith(str(package)+'/') for row in audit.values())
        assert {name:audit[name]['sha256'] for name in expected}==expected


@pytest.mark.parametrize('outcome',['success','changed','foreign','read-error'])
def test_listener_diagnostic_preserves_reads_results_and_exceptions(outcome):
    import gui_forward_client as client
    calls=[];marker=RuntimeError(outcome)
    class Original:
        def observe(self):calls.append('observe');return {'pid':123,'start':'42','namespace':(1,2)}
        def inodes(self):calls.append('inodes');return {9,3}
        def candidates(self,host,port):
            calls.append(('candidates',host,port))
            if outcome=='read-error':raise marker
            return [{'inode':3,'port':port}]
        def proof(self,host,port):
            self.observe();self.inodes();rows=self.candidates(host,port)
            if outcome in ('changed','foreign'):raise marker
            return rows
    module=SimpleNamespace(Listener=Original);trace={'events':[],'dropped':0}
    with client.listener_diagnostics(module,trace):
        if outcome=='success':
            result=module.Listener().proof('127.0.0.1',1234)
            result[0]['inode']=99
            assert trace['events'][-1]['value']==[{'inode':3,'port':1234}]
        else:
            with pytest.raises(RuntimeError) as raised:module.Listener().proof('127.0.0.1',1234)
            assert raised.value is marker
            assert trace['events'][-1]['error']==outcome
    assert module.Listener is Original
    assert calls==['observe','inodes',('candidates','127.0.0.1',1234)]
    assert trace['events'][1]['value']==[3,9]
    assert trace['dropped']==0


def test_listener_diagnostic_bounds_records_and_restores_on_error():
    import gui_forward_client as client
    class Original:
        def inodes(self):return {3}
    module=SimpleNamespace(Listener=Original);trace={'events':[],'dropped':0}
    with pytest.raises(ValueError):
        with client.listener_diagnostics(module,trace):
            for _ in range(260):assert module.Listener().inodes()=={3}
            raise ValueError('fixture interrupted')
    assert module.Listener is Original
    assert len(trace['events'])==256 and trace['dropped']==4
