"""Container-scoped qualification of the actual GUI OpenSSH TCP forwarder."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import time
import uuid

from dnlab_runtime.backend import Backend,labels
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import fingerprint
from nos_fixture import NosFixture
from management_service_diagnostics import private_json
from dnlab_multinode.services.jumphost_host import Worker
from dnlab_multinode.services.dns_host import Worker as DNSWorker
from management_ssh_probe import public_key

SOURCE=Path(__file__).resolve().parents[3]


class GuiFixture(NosFixture):
    def bind_response(self,value):
        current=super().bind_response(value);c=current['Config'];h=current['HostConfig']
        expected=value['effective_config'];desired=expected['HostConfig']
        image=self.backend.docker.request('GET','/images/'+self.spec['image']+'/json')
        env=dict(item.split('=',1) for item in image.get('Config',{}).get('Env') or [])
        env.update(item.split('=',1) for item in expected['Env'])
        if (current['Image']!=self.spec['image'] or c['Image']!=self.spec['image']
                or any(c.get(k)!=expected[k] for k in ('Entrypoint','Cmd','User','Labels'))
                or len(c.get('Env') or [])!=len(env) or dict(item.split('=',1) for item in c['Env'])!=env
                or h.get('NetworkMode')!='host' or h.get('PidMode','')!='' or h.get('IpcMode')!='private'
                or h.get('Privileged') is not False or h.get('ReadonlyRootfs') is not True
                or h.get('CapAdd') not in (None,[]) or h.get('CapDrop')!=['ALL']
                or h.get('PortBindings') not in (None,{}) or h.get('RestartPolicy',{}).get('Name')!='no'
                or sorted(h.get('Binds') or [])!=sorted(desired['Binds'])):
            raise RuntimeError('GUI fixture original configuration differs')
        return current


def pending(root):
    root=Path(root)
    if not (root/'gui-client').exists():return False
    path=root/'gui-forwarding.json'
    try:return not path.exists() or json.loads(path.read_text()).get('cleanup_verified') is not True
    except (OSError,ValueError,AttributeError,TypeError):return True



def generation(value):
    state=value['State'];pid=state.get('Pid')
    if state.get('Running') is not True or type(pid) is not int or pid<=0:
        raise RuntimeError('original GUI client PID1 not running')
    start=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
    ns=os.stat('/proc/'+str(pid)+'/ns/pid')
    return {'container_id':value['Id'],'pid':pid,'started_at':state['StartedAt'],'process_start':start,
            'pid_namespace':{'device':ns.st_dev,'inode':ns.st_ino}}


def probe(root,lab,bundle,key,image,*,http_target=None):
    root=Path(root);directory=root/'gui-client';directory.mkdir(mode=0o700)
    output=directory/'output';output.mkdir(mode=0o700);nonce=uuid.uuid4().hex
    jw=Worker(lab,directory=str(root/'jump'),management_directory=str(root/'management'))
    dw=DNSWorker(lab,directory=str(root/'dns'))
    def observe():
        jr=jw.read();dr=dw.read()
        if jr['config']!=bundle['jumphost'] or dr['config']!=bundle['dns']['config']:raise RuntimeError('GUI original service intent differs')
        jw.infrastructure(jr);jw.verify_extensions(jr);dw.infrastructure(dr);dns=dw.container(dr)
        _,proof=public_key(jw,jr)
        return {'jump':proof,'dns':{'id':dns['Id'],'nonce':dr['nonce'],'started_at':dns['State']['StartedAt']}}
    original=observe()
    targets=[{'role':'central-dns','ip':bundle['dns']['config']['ip']}]
    targets += [{'role':'management-'+name,'ip':row['ipv4']} for name,row in sorted(bundle['services']['dns']['management_resolvers'].items())]
    profile={'nonce':nonce,'lab':lab,'host':bundle['jumphost']['bind_ip'],'port':bundle['jumphost']['port'],
             'records':bundle['dns_probe']['records'],'targets':targets,
             'gui_root':'/opt/dnlab-gui','gui_output':'/run/gui-output','gui_modules':{
                 'app.services.'+name:hashlib.sha256((SOURCE/'src/gui/app/services'/ (name+'.py')).read_bytes()).hexdigest()
                 for name in ('webui_service','webui_listener')}}
    profile['gui_modules']['app.views.api.webui_routes']=hashlib.sha256((SOURCE/'src/gui/app/views/api/webui_routes.py').read_bytes()).hexdigest()
    if http_target is not None:profile['http_target']=http_target
    private_json(directory/'profile.json',profile)
    paths={
        SOURCE/'src/gui/app/services/webui_service.py':'/opt/dnlab-gui/app/services/webui_service.py',
        SOURCE/'src/gui/app/services/webui_listener.py':'/opt/dnlab-gui/app/services/webui_listener.py',
        SOURCE/'src/gui/app/views/api/webui_routes.py':'/opt/dnlab-gui/app/views/api/webui_routes.py',
        Path(__file__).with_name('gui_route_fixture.py'):'/run/gui_route_fixture.py',
        Path(__file__).with_name('gui_forward_client.py'):'/run/gui-client.py',
        SOURCE/'src/multinode/dnlab_multinode/services/management_dns_probe.py':'/run/gui-dns-wire.py',
        directory/'profile.json':'/run/gui-profile.json',Path(key['path']):'/run/gui-ssh-key'}
    hashes={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    request={'lab_id':lab,'node_id':'gui-forward-client','request_id':nonce,'action':'start','expected_revision':0}
    spec={'kind':'linux','image':image,'container_name':'drsp-gui-'+nonce[:12],'stop_timeout':10}
    backend=Backend()
    image_proof=backend.docker.request('GET','/images/'+image+'/json')
    if image_proof.get('Id')!=image or image_proof.get('Config',{}).get('Volumes'):
        raise RuntimeError('immutable GUI image without anonymous volumes required')
    config={'Image':image,'Entrypoint':['python','-u','/run/gui-client.py'],'Cmd':[],'User':'0:0',
            'Labels':{**(image_proof.get('Config',{}).get('Labels') or {}),**labels(request,spec),'io.dnlab.spike':'gui-forwarding'},
            'Env':['DNLABGUI_JUMPHOST_HOST='+profile['host'],'DNLABGUI_SSH_KEY=/run/gui-ssh-key','DNLABGUI_JUMPHOST_USER=labuser','DNLABGUI_LOG_DIR=/run/gui-output/logs','TOPOLOGIES_DIR=/run/gui-output/topologies','PYTHONDONTWRITEBYTECODE=1'],
            'HostConfig':{'NetworkMode':'host','CapDrop':['ALL'],'ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'},
              'Binds':[str(path)+':'+target+':ro' for path,target in paths.items()]+[str(output)+':/run/gui-output:rw']}}
    journal=Journal(directory);fixture=GuiFixture(journal,backend,request,spec)
    report={'phase':'planned','original':original,'request':request,'spec':spec,'source_hashes':hashes,'cleanup_verified':False}
    private_json(root/'gui-forwarding.json',report)
    try:
        if backend.docker.request('GET','/images/'+image+'/json')['Id']!=image:raise RuntimeError('immutable GUI image required')
        fixture.create(config);started=fixture.start()
        report['client_generation']=generation(started);private_json(root/'gui-forwarding.json',report)
        if observe()!=original:raise RuntimeError('GUI original services changed before permit')
        private_json(output/'permit.json',{'nonce':nonce})
        deadline=time.monotonic()+45
        while True:
            current=fixture.bind_response(fixture.get())
            if generation(current)!=report['client_generation']:raise RuntimeError('original GUI client process generation changed')
            path=output/'result.json'
            result=json.loads(path.read_text()) if path.exists() else None
            if result and result.get('nonce')!=nonce:raise RuntimeError('GUI fixture result nonce differs')
            if result and result.get('phase') in ('completed','failed'):
                report['client']=result;private_json(root/'gui-forwarding.json',report)
                if result['phase']!='completed' or not result.get('children_exited') or not result.get('route_api_verified'):raise RuntimeError('GUI forwarding client failed; original result retained')
                if len(result['answers'])!=len(targets)*len(profile['records']) or len(result['processes'])!=len(targets):raise RuntimeError('GUI forwarding result incomplete')
                if http_target is not None and not result.get('webui_http_verified'):
                    raise RuntimeError('original HTTP workload proxy verification missing')
                break
            if time.monotonic()>=deadline:raise RuntimeError('GUI forwarding result timeout')
            time.sleep(.1)
        if observe()!=original or any(hashlib.sha256(path.read_bytes()).hexdigest()!=hashes[str(path)] for path in paths):raise RuntimeError('GUI original proof or source changed')
        report['phase']='completed'
    except Exception as error:
        report.update(phase='failed',error_type=type(error).__name__,error=str(error))
        try:
            value=fixture.get()
            if value and value.get('container_id'):
                current=fixture.bind_response(value)
                report['failure_container']={k:current.get(k) for k in ('Id','Name','State')}
                logs=subprocess.run(['docker','logs','--tail','60',current['Id']],capture_output=True,text=True,timeout=5)
                report['failure_logs']={'exit_code':logs.returncode,'stdout':logs.stdout[-12000:],'stderr':logs.stderr[-12000:]}
        except Exception as diagnostic:report['diagnostic_error']=str(diagnostic)
        raise
    finally:
        try:
            value=fixture.get()
            if report.get('client_generation') and value and value.get('container_id'):
                current=fixture.bind_response(value)
                if current['State']['StartedAt']!=report['client_generation']['started_at']:
                    raise RuntimeError('GUI client restart conflicts with original cleanup generation')
            fixture.cleanup()
            report['cleanup_verified']=fixture.get() is None or fixture.get()['phase']=='cleaned'
        except Exception as error:
            report.update(cleanup_error_type=type(error).__name__,cleanup_error=str(error));raise
        finally:
            private_json(root/'gui-forwarding.json',report);journal.close()
    return report
