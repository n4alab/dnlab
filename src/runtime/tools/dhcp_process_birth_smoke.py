#!/usr/bin/env python3
"""Qualify dnsmasq daemon birth markers and stdin preflight, network isolated."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Docker
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'multinode'))
from dnlab_multinode.services.jumphost_host import DockerExecHTTP, DockerExecError, JournaledDHCPExec, JournaledDHCPMain, JournaledDHCPAssets, same_bind_mounts

IMAGE='sha256:de63a0cd8f1083ecab8d81ffcc3446227271b9677ad8dd2e08547704b57850da'


def save_json(path, value):
    """Atomic private fixture intent; errors never imply a completed mutation."""
    path=Path(path);temporary=path.parent/('.'+path.name+'-'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary.exists():temporary.unlink()


def validate_fixture_name(birth):
    """Only a nonce-derived dedicated name may be used for a new create."""
    nonce=birth.get('nonce')
    if (not isinstance(nonce,str) or len(nonce)!=32
            or any(ch not in '0123456789abcdef' for ch in nonce)
            or birth.get('name')!='drsp-dhbirth-'+nonce[:12]):
        raise RuntimeError('dedicated original fixture container name required before create')
    return birth['name']


def inspect_birth(docker, birth, save):
    config=birth['config'];identity=birth['id'];name=birth['name']
    value=docker.inspect(identity or name)
    named=docker.inspect(name) if identity else value
    if named and identity and named['Id']!=identity:
        raise RuntimeError('diagnostic container name replaced')
    if value:
        cfg=value['Config'];host=value['HostConfig']
        if (value['Image']!=birth['image'] or cfg['Labels']!=config['Labels']
                or cfg['Labels'].get('org.dnlab.dhcp-birth')!=birth['nonce']
                or cfg['Entrypoint']!=config['Entrypoint'] or cfg['Cmd']!=config['Cmd']
                or host['NetworkMode']!='none' or not same_bind_mounts(host['Binds'],config['HostConfig']['Binds'])
                or value['Name']!='/'+name):raise RuntimeError('diagnostic container birth differs')
        if identity and value['Id']!=identity:raise RuntimeError('container replaced')
    from urllib.parse import urlencode
    filters=json.dumps({'label':['org.dnlab.dhcp-birth='+birth['nonce']]})
    candidates=docker.request('GET','/containers/json?'+urlencode({'all':'1','filters':filters}))
    if not isinstance(candidates,list) or any(not isinstance(v,dict) for v in candidates):
        raise RuntimeError('invalid diagnostic birth inventory')
    ids=[v.get('Id') for v in candidates]
    if ids!=([value['Id']] if value else []):
        raise RuntimeError('ambiguous or renamed diagnostic birth')
    if value and not identity:
        if birth.get('create_status')=='not_attempted':
            raise RuntimeError('diagnostic birth exists without create intent')
        birth['id']=value['Id'];birth['create_status']='qualified';save()
    return value


def cleanup_fixture(docker, birth, save, *, wait_seconds=5):
    """Uncertain create + momentary absence is pending, never verified cleanup."""
    birth['cleanup_status']='cleanup_pending';save()
    deadline=time.monotonic()+wait_seconds
    while True:
        value=inspect_birth(docker,birth,save)
        if value:
            # A single create attempt is allowed; binding its original ID proves
            # that the formerly uncertain request has produced this generation.
            birth['cleanup_id']=value['Id'];save()
            if value['State']['Running']:
                current=inspect_birth(docker,birth,save)
                if not current or current['Id']!=birth['cleanup_id']:
                    raise RuntimeError('diagnostic birth disappeared before shutdown')
                docker.request('POST','/containers/'+current['Id']+'/kill?signal=SIGKILL')
                docker.request('POST','/containers/'+current['Id']+'/wait')
            current=inspect_birth(docker,birth,save)
            if current:
                if current['State']['Running']:raise RuntimeError('diagnostic shutdown unverified')
                docker.request('DELETE','/containers/'+current['Id'])
            if inspect_birth(docker,birth,save) is not None:
                raise RuntimeError('diagnostic birth remains after remove')
            birth['cleanup_status']='cleaned';save();return True
        if birth['id'] or birth.get('create_status')=='not_attempted':
            birth['cleanup_status']='cleaned';save();return True
        # No new create is sent, and no metadata is discarded on uncertainty.
        if time.monotonic()>=deadline:return False
        time.sleep(.1)


def recover_cleanup(output):
    root=Path(output);path=root/'intent.json';info=path.lstat()
    import stat
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
        raise RuntimeError('private original fixture journal required')
    birth=json.loads(path.read_text())
    if birth['image']!=IMAGE:raise RuntimeError('original pinned fixture image required')
    # Old uncertain intents remain uncertain; an old "cleanup verified" report
    # cannot prove that a timed-out create request was terminal.
    birth.setdefault('create_status','uncertain')
    result=cleanup_fixture(Docker(),birth,lambda:save_json(path,birth))
    save_json(root/'cleanup-recovery.json',{'verified':result,'status':birth['cleanup_status'],'id':birth['id']})
    if not result:raise RuntimeError('fixture create outcome still uncertain; cleanup_pending retained')
    return result


PIDFILE_SNAPSHOT_PROGRAM = r"""import json,os,stat
path='/run/dnlab-dnsmasq.pid';out={'path':path}
def identity(st):return {'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),'regular':stat.S_ISREG(st.st_mode),'directory':stat.S_ISDIR(st.st_mode),'symlink':stat.S_ISLNK(st.st_mode),'nlink':st.st_nlink}
def error(exc):return {'error_type':type(exc).__name__,'errno':getattr(exc,'errno',None)}
try:out['parent']=identity(os.stat('/run',follow_symlinks=False))
except OSError as exc:out['parent_error']=error(exc)
try:
 out['lstat']=identity(os.lstat(path));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:out['fstat']=identity(os.fstat(fd));out['text']=os.read(fd,128).decode(errors='replace')
 finally:os.close(fd)
except OSError as exc:out['read_error']=error(exc)
print(json.dumps(out,sort_keys=True))
"""


def absence_snapshot(command, pid_namespace, original=None, observed=None):
    """Read-only evidence, separate from the unchanged service authorization."""
    value={'captured_unix':time.time(),'original_service':original,'guard_observation':observed,
           'pid_namespace':{'device':pid_namespace.st_dev,'inode':pid_namespace.st_ino},
           'processes':[],'scan_races':0,'scan_errors':[]}
    try:
        result=command(['python3','-c',PIDFILE_SNAPSHOT_PROGRAM],check=False)
        value['pidfile_probe']={'returncode':result.returncode}
        if result.returncode==0:value['pidfile_probe']['snapshot']=json.loads(result.stdout)
    except Exception as error:value['pidfile_probe']={'error_type':type(error).__name__}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:
            scope=os.stat(path/'ns/pid')
            if (scope.st_dev,scope.st_ino)!=(pid_namespace.st_dev,pid_namespace.st_ino):continue
            status=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
            row={'host_pid':int(path.name),'namespace_pids':status.get('NSpid','').split(),
                 'state':status['State'].strip(),'comm':(path/'comm').read_text().strip(),
                 'start':(path/'stat').read_text().rsplit(')',1)[1].split()[19],
                 'uids':status['Uid'].split(),'gids':status['Gid'].split()}
            for name in ('pid','net','mnt'):
                scope=os.stat(path/'ns'/name);row[name+'_namespace']={'device':scope.st_dev,'inode':scope.st_ino}
            value['processes'].append(row)
        except (FileNotFoundError,ProcessLookupError):value['scan_races']+=1
        except OSError as error:value['scan_errors'].append({'host_pid':int(path.name),'error_type':type(error).__name__,'errno':error.errno})
    return value


def fixture_process_inventory(pid_namespace):
    """Inventory the original PID namespace; unreadable live entries fail closed."""
    expected={'device':pid_namespace.st_dev,'inode':pid_namespace.st_ino}
    rows=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():continue
        try:
            scope=os.stat(path/'ns/pid')
            if {'device':scope.st_dev,'inode':scope.st_ino}!=expected:continue
            status=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
            start=(path/'stat').read_text().rsplit(')',1)[1].split()[19]
            row={'host_pid':int(path.name),'namespace_pids':status.get('NSpid','').split(),
                 'state':status['State'].strip(),'comm':(path/'comm').read_text().strip(),'start':start}
            if not row['state'].startswith('Z'):
                info=os.stat(path/'exe')
                row['executable']={'device':info.st_dev,'inode':info.st_ino,
                    'sha256':hashlib.sha256((path/'exe').read_bytes()).hexdigest()}
            # Detect reuse or exit during collection instead of authorizing a
            # live row assembled from two different process generations.
            if (path/'stat').read_text().rsplit(')',1)[1].split()[19]!=start:
                raise RuntimeError('fixture process changed during inventory')
            rows.append(row)
        except (FileNotFoundError,ProcessLookupError):
            # A vanished process contributes no live service. A live process
            # whose namespace/executable is unreadable is not verified absent.
            try:
                status=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
                if not status['State'].strip().startswith('Z'):
                    raise RuntimeError('fixture live process inspection incomplete')
            except (FileNotFoundError,ProcessLookupError):pass
    return {'pid_namespace':expected,'complete':True,'processes':rows}


def qualify_fixture_absence(service, container, original_pidfile, current_pidfile, inventory, events, pidfd):
    """Only a pinned, exited original daemon permits the stale original file."""
    try:
        if (container!=service['container'] or inventory['complete'] is not True
                or inventory['pid_namespace']!=container['pid_namespace']
                or not any(fd==pidfd and flags & select.POLLIN
                           and not flags & (select.POLLERR|select.POLLNVAL) for fd,flags in events)):
            raise ValueError()
        original=original_pidfile['fstat'];parent=original_pidfile['parent']
        if (set(original_pidfile)!={'path','lstat','fstat','text','parent'}
                or original_pidfile['path']!='/run/dnlab-dnsmasq.pid'
                or original_pidfile['lstat']!=original
                or original['regular'] is not True or original['symlink'] is not False
                or original['uid']!=int(service['uids'][0]) or original['mode']!='0o644'
                or original['nlink']!=1 or original_pidfile['text']!=str(service['pid'])+'\n'
                or parent['directory'] is not True or parent['symlink'] is not False
                or parent['uid']!=0 or parent['mode']!='0o755'):
            raise ValueError()
        absent={'path':original_pidfile['path'],'parent':parent,
                'read_error':{'error_type':'FileNotFoundError','errno':2}}
        if current_pidfile!=original_pidfile and current_pidfile!=absent:raise ValueError()
        seen=set()
        for row in inventory['processes']:
            host=row['host_pid'];local=row['namespace_pids'][-1]
            if type(host) is not int or host<=0 or host in seen or not local.isdecimal() or not row['state']:
                raise ValueError()
            seen.add(host);zombie=row['state'].startswith('Z')
            if host==service['host_pid'] or local==str(service['pid']):
                if (host!=service['host_pid'] or local!=str(service['pid'])
                        or row['start']!=service['start'] or not zombie):raise ValueError()
            if not zombie:
                executable=row['executable']
                if (row['comm']=='dnsmasq' or executable['sha256']==service['binary_sha256']
                        or {k:executable[k] for k in ('device','inode')}==service['executable']):
                    raise ValueError()
        return {'original_exit_verified':True,'live_dnsmasq_count':0,
                'original_pidfile_retained':current_pidfile==original_pidfile}
    except (KeyError,TypeError,ValueError,IndexError,AttributeError):
        raise RuntimeError('fixture daemon absence is unqualified') from None


def structural_assets_gate(root, assets, birth, report, proposed, container_proof, stopped_service, command, save):
    receipt={'exit_verified':True,'service':report['daemon']}
    desired={'main':proposed,'hosts':'# new hosts\n'*100,'options':'# new options\n'*100}
    birth['asset_write']=JournaledDHCPAssets.prepare(assets,birth['assets_previous'],desired,
        container_proof(),receipt,uuid.uuid4().hex)
    save('intent.json',birth)
    def preflight():
        stopped_service();current=container_proof()
        directory=Path('/proc')/str(current['init_pid'])/'root/etc/dnlab-dhcp'
        for name,previous in birth['assets_previous'].items():
            info=(directory/name).stat()
            if {'device':info.st_dev,'inode':info.st_ino}!=previous['identity']:
                raise RuntimeError('original structural asset mount replaced')
        main=Path('/proc')/str(current['init_pid'])/'root/etc/dnsmasq.d/dnlab-mgmt.conf'
        if {'device':main.stat().st_dev,'inode':main.stat().st_ino}!=birth['assets_previous']['main']['identity']:
            raise RuntimeError('original individual main bind replaced')
        return {'container':current,'service_exit':receipt}
    from dnlab_multinode.services import jumphost_host as module
    class LostAssetReply(RuntimeError):pass
    report['asset_recoveries']=[]
    for name in JournaledDHCPAssets.NAMES:
        for fault in ('pwrite','ftruncate'):
            identity=birth['assets_previous'][name]['identity'];operation=getattr(module.os,fault);armed=[True]
            def interrupted(fd,*args):
                info=os.fstat(fd);chosen=armed[0] and {'device':info.st_dev,'inode':info.st_ino}==identity
                if chosen and fault=='pwrite':result=operation(fd,args[0][:3],args[1])
                else:result=operation(fd,*args)
                if chosen:armed[0]=False;raise LostAssetReply(name+'-'+fault+' reply lost')
                return result
            setattr(module.os,fault,interrupted)
            try:
                try:JournaledDHCPAssets(assets,birth['asset_write'],lambda:save('intent.json',birth),preflight).run()
                except LostAssetReply:pass
                else:raise RuntimeError('asset fault not exercised: '+name+'-'+fault)
            finally:setattr(module.os,fault,operation)
            birth=json.loads((root/'intent.json').read_text())
            verifier=JournaledDHCPAssets(assets,birth['asset_write'],lambda:save('intent.json',birth),preflight)
            verifier.verify()  # Own partial files qualify without mutation or external preflight.
            report['asset_recoveries'].append(name+'-'+fault+'-reply-lost-and-journal-reopened')
    runner=JournaledDHCPAssets(assets,birth['asset_write'],lambda:save('intent.json',birth),preflight)
    result=runner.run();assert runner.run()==result
    for name,desired_content in desired.items():
        if command(['cat','/etc/dnlab-dhcp/'+name]).stdout!=desired_content:
            raise RuntimeError('committed structural content not visible in directory bind')
        info=(assets/name).stat()
        assert {'device':info.st_dev,'inode':info.st_ino}==birth['assets_previous'][name]['identity']
    assert command(['cat','/etc/dnsmasq.d/dnlab-mgmt.conf']).stdout==desired['main']
    report['structural_assets']={'phase':birth['asset_write']['phase'],'same_inodes':True,
        'all_mounted_contents_verified':True,'committed_retry_unchanged':True,
        'original_daemon_remains_stopped':stopped_service()['original_exit_verified']}
    return birth


def run(output,exec_api=False,journaled_exec=False,journaled_main=False,absence_diagnostic=False,journaled_assets=False):
    root=Path(output);root.mkdir(mode=0o700)
    nonce=uuid.uuid4().hex;container_name='drsp-dhbirth-'+nonce[:12]
    assets=root/'assets' if journaled_main else root
    if journaled_main:assets.mkdir(mode=0o755);assets.chmod(0o755)
    main=assets/'main';content='port=0\npid-file=/run/dnlab-dnsmasq.pid\nlog-facility=/run/dnlab-dhcp.log\n'
    if journaled_assets:
        content+='dhcp-hostsfile=/etc/dnlab-dhcp/hosts\ndhcp-optsfile=/etc/dnlab-dhcp/options\n'
        for asset_name in ('hosts','options'):
            (assets/asset_name).write_text('# old '+asset_name+'\n');(assets/asset_name).chmod(0o644)
    main.write_text(content);main.chmod(0o644)
    main_identity=(main.stat().st_dev,main.stat().st_ino)
    docker=Docker();birth={'name':container_name,'nonce':nonce,'id':None,'image':IMAGE,'create_status':'not_attempted'}
    report={'scope':'daemon birth and stdin syntax preflight only; no DHCP/network gate',
        'image':IMAGE,'status':'running','network':'none'}
    def save(name,value):save_json(root/name,value)
    events=[];original_request=docker.request
    def traced_request(method,path,*args,**kwargs):
        row={'method':method,'path':path.split('?')[0],'started_unix':time.time()}
        events.append(row);save('docker-events.json',events);started=time.monotonic()
        try:
            result=original_request(method,path,*args,**kwargs);row['outcome']='response';return result
        except BaseException as error:
            row.update(outcome='error',error_type=type(error).__name__);raise
        finally:
            row['elapsed_seconds']=time.monotonic()-started;save('docker-events.json',events)
    docker.request=traced_request
    if journaled_assets:
        birth['assets_previous']={name:{'identity':{'device':(assets/name).stat().st_dev,'inode':(assets/name).stat().st_ino},
            'content':(assets/name).read_text()} for name in JournaledDHCPAssets.NAMES}
    config={'Image':IMAGE,'Labels':{'org.dnlab.dhcp-birth':nonce},'Entrypoint':['python3','-c'],
        'Cmd':['import time;time.sleep(120)'],'HostConfig':{'NetworkMode':'none',
            'Binds':[str(main)+':/etc/dnsmasq.d/dnlab-mgmt.conf:ro']}}
    if journaled_assets:config['HostConfig']['Binds'].append(str(assets)+':/etc/dnlab-dhcp:ro')
    image=docker.request('GET','/images/'+IMAGE+'/json')
    if image['Id']!=IMAGE:raise RuntimeError('immutable diagnostic image differs')
    config['Labels']=dict(image.get('Config',{}).get('Labels') or {},**config['Labels'])
    birth['config']=config;save('intent.json',birth)
    def inspect():return inspect_birth(docker,birth,lambda:save('intent.json',birth))
    def command(argv,check=True,**kwargs):
        value=inspect()
        if not value or not value['State']['Running']:raise RuntimeError('original container unavailable')
        p=subprocess.run(['docker','exec',value['Id'],*argv],text=True,capture_output=True,timeout=10,**kwargs)
        if check and p.returncode:raise RuntimeError(p.stderr)
        return p
    def container_proof():
        value=inspect();state=value['State']
        if not state['Running'] or state.get('Paused'):raise RuntimeError('original fixture not runnable')
        process=Path('/proc')/str(state['Pid'])
        def identity(name):
            st=os.stat(process/'ns'/name);return {'device':st.st_dev,'inode':st.st_ino}
        return {'id':value['Id'],'image':value['Image'],'started_at':state['StartedAt'],
            'init_pid':state['Pid'],'init_start':(process/'stat').read_text().rsplit(')',1)[1].split()[19],
            'pid_namespace':identity('pid'),'mount_namespace':identity('mnt'),'net_namespace':identity('net')}
    observation={}
    def observe_daemon():
        p=command(['python3','-c',"import json,pathlib; p=pathlib.Path('/run/dnlab-dnsmasq.pid'); print(json.dumps({'pid':int(p.read_text().strip())} if p.exists() else {'absent':True}))"])
        local=json.loads(p.stdout);matches=[];daemons=[]
        if absence_diagnostic:observation.clear();observation.update(pidfile=local,processes=[])
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():continue
            try:
                scope=os.stat(path/'ns/pid')
                if (scope.st_dev,scope.st_ino)!=(pidns.st_dev,pidns.st_ino):continue
                status=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
                if absence_diagnostic:
                    observation['processes'].append({'host_pid':int(path.name),'namespace_pids':status.get('NSpid','').split(),
                        'state':status['State'].strip(),'comm':(path/'comm').read_text().strip(),
                        'start':(path/'stat').read_text().rsplit(')',1)[1].split()[19]})
                if status['State'].strip().startswith('Z'):continue
                if (path/'comm').read_text().strip()=='dnsmasq':daemons.append(int(path.name))
                if status.get('NSpid','').split()[-1:]==[str(local.get('pid'))]:matches.append((path,status))
            except (FileNotFoundError,ProcessLookupError):continue
        if absence_diagnostic:
            observation.update(matches=[int(path.name) for path,status in matches],daemons=list(daemons))
        if local.get('absent'):
            if daemons:raise RuntimeError('unbound daemon exists without its PID file')
            return None
        if len(matches)!=1 or len(daemons)!=1:raise RuntimeError('daemon mapping missing or ambiguous')
        path,status=matches[0];hostpid=int(path.name)
        start=(path/'stat').read_text().rsplit(')',1)[1].split()[19]
        expected=('DNLAB_DHCP_OPERATION_NONCE='+birth['daemon_nonce']).encode()
        environment=(path/'environ').read_bytes().split(b'\0');found=environment.count(expected)
        value={'host_pid':hostpid,'pid':local['pid'],'start':start,'uids':status['Uid'].split(),
            'gids':status['Gid'].split(),'command':(path/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
            'nonce_occurrences':found,'nonce_observable':found==1,
            'binary_sha256':hashlib.sha256((path/'exe').read_bytes()).hexdigest(),
            'operation_nonce':birth['daemon_nonce'],'container':container_proof()}
        executable=os.stat(path/'exe');value['executable']={'device':executable.st_dev,'inode':executable.st_ino}
        if (found!=1 or value['uids']!=['65534']*4 or value['gids']!=['30']*4
                or value['binary_sha256']!='fdb17a6b5511ce142f3b16bf8e212fe8b05d7abcc2ca2fcdec1aa033691d0196'
                or value['command']!=['dnsmasq','--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf']
                or (path/'stat').read_text().rsplit(')',1)[1].split()[19]!=start):
            raise RuntimeError('daemon birth qualification differs')
        return value
    try:
        validate_fixture_name(birth)
        if inspect() is not None:raise RuntimeError('diagnostic name occupied before create')
        birth['create_status']='uncertain';save('intent.json',birth)
        birth['id']=docker.create(validate_fixture_name(birth),config)['Id'];birth['create_status']='qualified';save('intent.json',birth)
        docker.request('POST','/containers/'+birth['id']+'/start');value=inspect()
        init=value['State']['Pid'];pidns=os.stat(f'/proc/{init}/ns/pid')
        # Syntax-check both valid and invalid input before launching a daemon.
        for label,text,expected in [('valid',content,0),('invalid','not-a-dnsmasq-option=1\n',1)]:
            inspect()
            p=subprocess.run(['docker','exec','-i',birth['id'],'dnsmasq','--test','--conf-file=-'],
                input=text,text=True,capture_output=True,timeout=10)
            save('stdin-'+label+'.json',{'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
            if (p.returncode==0)!=(expected==0):raise RuntimeError('stdin syntax preflight outcome differs')
        inspect();birth['daemon_nonce']=uuid.uuid4().hex;save('intent.json',birth)
        if journaled_exec:
            birth['launch']={'nonce':birth['daemon_nonce'],'container':container_proof(),'phase':'intent',
                'exec_id':None,'create_attempts':0,'start_attempted':False,'observed_exec_ids':[],'service':None}
            save('intent.json',birth)
            def preflight():
                if ((main.stat().st_dev,main.stat().st_ino)!=main_identity or main.read_text()!=content):
                    raise RuntimeError('original mounted config changed')
                return {'container':container_proof(),'exec_ids':inspect().get('ExecIDs') or []}
            class LostReply(RuntimeError):pass
            class FaultTransport:
                def __init__(self):self.base=DockerExecHTTP();self.fault=None;self.creates=0;self.starts=0
                def call(self,method,path,payload=None,**kwargs):
                    value=self.base.call(method,path,payload,**kwargs)
                    if method=='POST' and path.endswith('/exec'):
                        self.creates+=1
                        if self.fault=='create':self.fault=None;raise LostReply('discarded create reply')
                    if method=='POST' and path.endswith('/start'):
                        self.starts+=1
                        if self.fault=='start':self.fault=None;raise LostReply('discarded start reply')
                    return value
            transport=FaultTransport();report['journal_recoveries']=[]
            for fault in ('create','start'):
                transport.fault=fault
                try:JournaledDHCPExec(birth['launch'],lambda:save('intent.json',birth),preflight,observe_daemon,docker=transport).run()
                except LostReply:pass
                else:raise RuntimeError('expected fault was not exercised: '+fault)
                birth=json.loads((root/'intent.json').read_text())
                report['journal_recoveries'].append(fault+'-reply-lost-and-journal-reopened')
            runner=JournaledDHCPExec(birth['launch'],lambda:save('intent.json',birth),preflight,observe_daemon,docker=transport)
            service=runner.run()
            if runner.run()!=service or transport.creates!=1 or transport.starts!=1:
                raise RuntimeError('journal retry recreated an exec or process')
            report['journal_exec']={'exec_id':birth['launch']['exec_id'],'creates':transport.creates,
                'starts':transport.starts,'phase':birth['launch']['phase'],'committed_retry_same_service':True}
            save('exec-after.json',transport.base.call('GET','/exec/'+birth['launch']['exec_id']+'/json'))
        elif exec_api:
            transport=DockerExecHTTP()
            payload={'Cmd':['env','DNLAB_DHCP_OPERATION_NONCE='+birth['daemon_nonce'],
                'dnsmasq','--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf'],
                'User':'0','AttachStdin':False,'AttachStdout':False,'AttachStderr':False,'Tty':False,'Privileged':False}
            birth['exec_payload']=payload;save('intent.json',birth)
            created=transport.call('POST','/containers/'+birth['id']+'/exec',payload)
            birth['exec_id']=created['Id'];save('intent.json',birth)
            before=transport.call('GET','/exec/'+birth['exec_id']+'/json');save('exec-before.json',before)
            visible=inspect().get('ExecIDs') or []
            report['exec_visible_before_start']=birth['exec_id'] in visible
            report['exec_ids_before_start']=visible
            transport.call('POST','/exec/'+birth['exec_id']+'/start',{'Detach':True,'Tty':False})
            deadline=time.monotonic()+5
            while True:
                after=transport.call('GET','/exec/'+birth['exec_id']+'/json')
                if not after['Running']:break
                if time.monotonic()>=deadline:raise RuntimeError('daemon launcher exec did not finish')
                time.sleep(.05)
            save('exec-after.json',after)
            if after['ExitCode']!=0:raise RuntimeError('daemon launcher exec failed')
            try:
                transport.call('POST','/exec/'+birth['exec_id']+'/start',{'Detach':True,'Tty':False})
                report['exec_replay_refused']=False
            except DockerExecError as error:
                report['exec_replay_status']=error.status
                report['exec_replay_refused']=error.status==409
        else:
            p=subprocess.run(['docker','exec','-e','DNLAB_DHCP_OPERATION_NONCE='+birth['daemon_nonce'],
                birth['id'],'dnsmasq','--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf'],text=True,capture_output=True,timeout=10)
            save('launch.json',{'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
            if p.returncode:raise RuntimeError('diagnostic dnsmasq launch failed')
        report['daemon']=observe_daemon()
        if report['daemon'] is None:raise RuntimeError('daemon absent after launch')
        hostpid=report['daemon']['host_pid'];start=report['daemon']['start'];path=Path('/proc')/str(hostpid)
        save('daemon.json',report['daemon'])
        # No environment dump: retain only the exact nonce equality result.
        inspect();fd=os.pidfd_open(hostpid)
        try:
            if (path/'stat').read_text().rsplit(')',1)[1].split()[19]!=start:raise RuntimeError('daemon replaced before TERM')
            if journaled_main:
                proposed=content+'# structural journal canary\n'*1000
                p=subprocess.run(['docker','exec','-i',birth['id'],'dnsmasq','--test','--conf-file=-'],
                    input=proposed,text=True,capture_output=True,timeout=10)
                if p.returncode:raise RuntimeError('proposed main failed syntax check')
            if journaled_main:
                birth['pidfile_before_term']=json.loads(command(['python3','-c',PIDFILE_SNAPSHOT_PROGRAM]).stdout)
                save('intent.json',birth)
            if absence_diagnostic:
                save('absence-before-term.json',absence_snapshot(command,pidns,report['daemon'],dict(observation)))
            signal.pidfd_send_signal(fd,signal.SIGTERM)
            poll=select.poll();poll.register(fd,select.POLLIN)
            report['term_exit_verified']=bool(poll.poll(5000))
            if not report['term_exit_verified']:raise RuntimeError('daemon did not exit after TERM')
            def stopped_service():
                before=container_proof()
                current=json.loads(command(['python3','-c',PIDFILE_SNAPSHOT_PROGRAM]).stdout)
                inventory=fixture_process_inventory(pidns)
                result=qualify_fixture_absence(report['daemon'],before,birth['pidfile_before_term'],
                    current,inventory,poll.poll(0),fd)
                if container_proof()!=before:raise RuntimeError('fixture generation changed during absence check')
                save('qualified-absence.json',{'result':result,'inventory':inventory,'pidfile':current})
                return result
            if absence_diagnostic:
                try:
                    result=stopped_service()
                    report['absence_diagnostic']={'guard_returned_absent':result['original_exit_verified'],'main_write_attempted':False}
                finally:
                    save('absence-after-term.json',absence_snapshot(command,pidns,report['daemon'],dict(observation)))
            if journaled_assets:
                birth=structural_assets_gate(root,assets,birth,report,proposed,container_proof,stopped_service,command,save)
            elif journaled_main and not absence_diagnostic:
                receipt={'exit_verified':True,'service':report['daemon']}
                birth['main_write']={'nonce':uuid.uuid4().hex,'container':container_proof(),
                    'service_exit':receipt,'directory':JournaledDHCPMain.identity(assets.stat(),directory=True),
                    'file':JournaledDHCPMain.identity(main.stat()),'old':content,'new':proposed,
                    'phase':'intent','offset':0,'pending_end':None}
                save('intent.json',birth)
                def main_preflight():
                    if not any(flags & select.POLLIN and not flags & (select.POLLNVAL|select.POLLERR)
                               for pidfd,flags in poll.poll(0) if pidfd==fd):
                        raise RuntimeError('original daemon exit is no longer verified')
                    stopped_service()
                    mounted=Path('/proc')/str(init)/'root/etc/dnsmasq.d/dnlab-mgmt.conf'
                    if (mounted.stat().st_dev,mounted.stat().st_ino)!=main_identity:
                        raise RuntimeError('original individually mounted main replaced')
                    return {'container':container_proof(),'service_exit':receipt}
                from dnlab_multinode.services import jumphost_host as module
                class LostMainReply(RuntimeError):pass
                report['main_recoveries']=[]
                for fault in ('pwrite','ftruncate'):
                    operation=getattr(module.os,fault);armed=[True]
                    def interrupted(*args):
                        if fault=='pwrite' and armed[0]:
                            result=operation(args[0],args[1][:13],args[2])
                        else:result=operation(*args)
                        if armed[0]:armed[0]=False;raise LostMainReply('discarded main '+fault+' reply')
                        return result
                    setattr(module.os,fault,interrupted)
                    try:
                        try:JournaledDHCPMain(assets,birth['main_write'],lambda:save('intent.json',birth),main_preflight).run()
                        except LostMainReply:pass
                        else:raise RuntimeError('main mutation fault not exercised: '+fault)
                    finally:setattr(module.os,fault,operation)
                    birth=json.loads((root/'intent.json').read_text())
                    report['main_recoveries'].append(fault+'-reply-lost-and-journal-reopened')
                runner=JournaledDHCPMain(assets,birth['main_write'],lambda:save('intent.json',birth),main_preflight)
                result=runner.run();assert runner.run()==result
                actual=command(['cat','/etc/dnsmasq.d/dnlab-mgmt.conf']).stdout
                if actual!=proposed or (main.stat().st_dev,main.stat().st_ino)!=main_identity:
                    raise RuntimeError('container bind does not expose the committed original inode')
                report['main_write']={'phase':birth['main_write']['phase'],'same_inode':True,
                    'bind_content_verified':True,'new_content_sha256':hashlib.sha256(proposed.encode()).hexdigest(),
                    'daemon_remains_stopped':stopped_service()['original_exit_verified'],'retry_unchanged':True}

        finally:os.close(fd)
        report['container_preserved']=inspect()['State']['Pid']==init
        if exec_api and (not report['exec_visible_before_start'] or not report['exec_replay_refused']):
            raise RuntimeError('Docker exec identity/replay contract differs')
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error_type']=type(error).__name__;report['error']=str(error);raise
    finally:
        try:
            report['cleanup_verified']=cleanup_fixture(docker,birth,lambda:save('intent.json',birth))
            report['cleanup_status']=birth['cleanup_status']
            if not report['cleanup_verified'] and report['status']=='passed':
                report['status']='failed';raise RuntimeError('fixture create outcome uncertain; cleanup_pending retained')
        except BaseException as error:
            report.update(cleanup_verified=False,cleanup_status='cleanup_pending',cleanup_error_type=type(error).__name__)
            raise
        finally:save('report.json',report)
        print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report['cleanup_verified']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    parser.add_argument('--recover-cleanup',action='store_true')
    parser.add_argument('--absence-diagnostic',action='store_true')
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--exec-api',action='store_true')
    modes.add_argument('--journaled-exec',action='store_true');modes.add_argument('--journaled-main',action='store_true');modes.add_argument('--journaled-assets',action='store_true');args=parser.parse_args()
    if args.absence_diagnostic and (not args.journaled_main or args.recover_cleanup):
        parser.error('absence diagnostic requires journaled-main and cannot run cleanup recovery')
    if args.recover_cleanup:
        if args.exec_api or args.journaled_exec or args.journaled_main or args.journaled_assets:parser.error('cleanup recovery cannot launch a canary')
        print(recover_cleanup(args.output))
    else:run(args.output,exec_api=args.exec_api,journaled_exec=args.journaled_exec,journaled_main=args.journaled_main or args.journaled_assets,absence_diagnostic=args.absence_diagnostic,journaled_assets=args.journaled_assets)
