"""PID1 program for a dedicated GUI/OpenSSH forwarding fixture container."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import tempfile
import time

@contextmanager
def listener_diagnostics(module,trace):
    """Record existing reads only; preserve the original proof and exceptions."""
    original=module.Listener
    def record(method,call):
        event={'method':method,'monotonic_ns':time.monotonic_ns()}
        try:
            result=call()
        except Exception as error:
            event.update(error_type=type(error).__name__,error=str(error))
            raise
        else:
            event['value']=deepcopy(sorted(result) if isinstance(result,set) else result)
            return result
        finally:
            if len(trace['events'])<256:trace['events'].append(event)
            else:trace['dropped']+=1
    class Diagnostic(original):
        def observe(self):return record('observe',lambda:super(Diagnostic,self).observe())
        def inodes(self):return record('inodes',lambda:super(Diagnostic,self).inodes())
        def candidates(self,host,port):return record('candidates',lambda:super(Diagnostic,self).candidates(host,port))
        def proof(self,host,port):return record('proof',lambda:super(Diagnostic,self).proof(host,port))
    module.Listener=Diagnostic
    try:yield
    finally:module.Listener=original


def writable_paths(profile,settings=None):
    output=Path(profile['gui_output'])
    if not output.is_absolute() or output.resolve(strict=True)!=output:
        raise RuntimeError('GUI output path differs')
    result={}
    for field,environment,child in (('TOPOLOGIES_DIR','TOPOLOGIES_DIR','topologies'),('LOG_DIR','DNLABGUI_LOG_DIR','logs')):
        wanted=output/child
        if os.environ.get(environment)!=str(wanted):raise RuntimeError('GUI writable environment differs: '+field)
        if wanted.is_symlink():raise RuntimeError('GUI writable path is a symlink: '+field)
        wanted.mkdir(mode=0o700,exist_ok=True)
        if not wanted.is_dir() or wanted.resolve(strict=True)!=wanted:
            raise RuntimeError('GUI writable path differs: '+field)
        if settings is not None and Path(getattr(settings,field))!=wanted:
            raise RuntimeError('GUI configured path differs: '+field)
        fd,probe=tempfile.mkstemp(prefix='.writable-',dir=wanted)
        try:
            os.write(fd,b'fixture');os.fsync(fd)
        finally:
            os.close(fd);os.unlink(probe)
        result[field]=str(wanted)
    return result


def bootstrap(profile):
    root=Path(profile['gui_root']).resolve(strict=True)
    if not (root/'app/__init__.py').is_file():raise RuntimeError('GUI package missing')
    expected=profile['gui_modules']
    names={'app.services.webui_service','app.services.webui_listener','app.views.api.webui_routes'}
    if set(expected)!=names:raise RuntimeError('GUI module manifest differs')
    for name,digest in expected.items():
        path=root.joinpath(*name.split('.')).with_suffix('.py')
        if path.resolve(strict=True)!=path or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('GUI module source differs: '+name)
    writable_paths(profile)
    sys.path.insert(0,str(root))
    service=importlib.import_module('app.services.webui_service')
    importlib.import_module('app.views.api.webui_routes')
    audit={}
    for name in ('app','app.services','app.config',*sorted(names)):
        loaded=sys.modules[name];path=Path(loaded.__file__).resolve()
        wanted=root.joinpath(*name.split('.'))
        wanted=wanted/'__init__.py' if name in ('app','app.services') else wanted.with_suffix('.py')
        if path!=wanted:raise RuntimeError('GUI loaded module origin differs: '+name)
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if name in expected and digest!=expected[name]:raise RuntimeError('GUI loaded module hash differs: '+name)
        audit[name]={'path':str(path),'sha256':digest}
    writable_paths(profile,sys.modules['app.config'].settings)
    return service.WebUIService,audit

stopping=False

def stop(*args):
    global stopping
    stopping=True


def save(path,value):
    fd,temporary=tempfile.mkstemp(dir=path.parent,prefix='.gui-')
    with os.fdopen(fd,'w') as stream:
        os.fchmod(stream.fileno(),0o600);json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def query(port,record,wire):
    token=int.from_bytes(os.urandom(2),'big')
    packet=struct.pack('!HHHHHH',token,0x100,1,0,0,0)+wire.wire_name(record['name'])
    packet+=struct.pack('!HH',1 if ipaddress.ip_address(record['address']).version==4 else 28,1)
    with socket.create_connection(('127.0.0.1',port),timeout=4) as stream:
        stream.settimeout(4);stream.sendall(struct.pack('!H',len(packet))+packet)
        def read(count):
            data=b''
            while len(data)<count:
                part=stream.recv(count-len(data))
                if not part:raise RuntimeError('tunnel DNS response truncated')
                data+=part
            return data
        size=int.from_bytes(read(2),'big')
        if not 12<=size<=4096:raise RuntimeError('tunnel DNS response size differs')
        return wire.validate_response(read(size),token,record['name'],record['address'])


def main():
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    profile=json.loads(Path('/run/gui-profile.json').read_text());out=Path('/run/gui-output/result.json')
    spec=importlib.util.spec_from_file_location('original_dns_wire','/run/gui-dns-wire.py')
    wire=importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)
    report={'phase':'waiting','nonce':profile['nonce'],'answers':[],'processes':[],'webui_http_verified':False,'route_api_verified':False,'listener_trace':{'events':[],'dropped':0}}
    service=None;api=None;children=[];failed=None
    save(out,report)
    try:
        service_class,audit=bootstrap(profile)
        report['bootstrap']=audit;report['writable_paths']=writable_paths(profile);save(out,report)
        service=service_class()
        deadline=time.monotonic()+30
        while not stopping:
            permit=Path('/run/gui-output/permit.json')
            if permit.exists() and json.loads(permit.read_text())=={'nonce':profile['nonce']}:break
            if time.monotonic()>=deadline:raise RuntimeError('GUI start permit missing')
            time.sleep(.05)
        if stopping:raise RuntimeError('GUI fixture stopped before permit')
        report['phase']='probing';save(out,report);previous=None
        from gui_route_fixture import route_client
        with route_client(profile,service) as api, listener_diagnostics(sys.modules['app.services.webui_service'],report['listener_trace']):
            for target in profile['targets']:
                if stopping:raise RuntimeError('GUI fixture interrupted')
                tunnel=api.open(target);children.append(tunnel.process)
                if previous:
                    if tunnel.token==previous.token or previous.process.poll() is None or service.get(previous.token) is not None:
                        raise RuntimeError('GUI tunnel destination replacement incomplete')
                if api.open(target) is not tunnel:raise RuntimeError('GUI unchanged target did not reuse tunnel')
                start=Path('/proc/'+str(tunnel.process.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
                report['processes'].append({'pid':tunnel.process.pid,'start':start,'target':target,'token_sha256':hashlib.sha256(tunnel.token.encode()).hexdigest()})
                save(out,report)
                for record in profile['records']:
                    answer=query(tunnel.local_port,record,wire)
                    report['answers'].append(dict(answer,target=target));save(out,report)
                previous=tunnel
            if profile.get('http_target'):
                service.shutdown()
                tunnel,proof=api.http_get(profile['http_target']);children.append(tunnel.process)
                report['http_workload_response']=proof;report['webui_http_verified']=True
                report['http_ssh_process']={'pid':tunnel.process.pid,'start':Path('/proc/'+str(tunnel.process.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]}
            report['route_api']=api.evidence;report['route_api_verified']=True
        report['phase']='completed'
    except Exception as error:
        failed=error;report.update(phase='failed',error_type=type(error).__name__,error=str(error))
        if api is not None:report['route_api']=api.evidence
    finally:
        if service is not None:service.shutdown()
        report['children_exited']=all(p.poll() is not None for p in children)
        report['child_exit_codes']=[p.returncode for p in children]
        if not report['children_exited']:
            report.update(phase='failed',error='original GUI SSH child exit not verified');failed=RuntimeError(report['error'])
        save(out,report)
    # Keep PID1 alive until the original qualified owner observes the result.
    deadline=time.monotonic()+60
    while not stopping and time.monotonic()<deadline:time.sleep(.05)
    if not stopping:raise RuntimeError('GUI fixture stop not received')
    if failed:raise failed


if __name__=='__main__':main()
