"""Qualify only the configured image-build loopback healthcheck processes.

No process is launched and no Docker-exec parentage is inferred. The exact
commands, pinned shell/interpreter, import environment, credentials, sources,
namespace/cgroup and original API generation must all match. A disappeared or
incomplete process is a conflict, never an exemption for arbitrary shell/Python.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
from pathlib import Path

from cleanup_container_observer import config_digest
from cleanup_healthcheck import HealthcheckProcess
from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import digest, fields, require

SCRIPT="import urllib.request; urllib.request.urlopen('http://127.0.0.1:8082/health', timeout=3).read()"
COMMAND='python -c "'+SCRIPT+'"'
TEST=['CMD-SHELL',COMMAND]
ARGV=dict(shell=('/bin/sh','-c',COMMAND),python=('python','-c',SCRIPT))
HASHES={name:hashlib.sha256(b'\0'.join(word.encode() for word in argv)+b'\0').hexdigest() for name,argv in ARGV.items()}
KIND='qualified-image-build-healthcheck-v1'


def stable_inspect(value):
    return dict(container_id=value['Id'],image_id=value['Image'],config_sha256=config_digest(value),
        restart_count=value['RestartCount'],state={key:value['State'].get(key) for key in
        ('Pid','Running','Status','StartedAt','FinishedAt','ExitCode','OOMKilled','Error')},
        networks=value['NetworkSettings']['Networks'])


class ImageBuildHealthcheckProcess(HealthcheckProcess):
    def _view(self, pid):
        view=super()._view(pid)
        raw=(Path('/proc')/str(pid)/'stat').read_bytes()
        parts=raw.rsplit(b')',1)[1].split()
        require(parts[19].decode()==view['start_ticks'], 'healthcheck process changed during parent observation')
        view['parent_pid']=int(parts[1])
        require(view['parent_pid']>0, 'qualified healthcheck parent PID required')
        return view


class ImageBuildHealthcheck:
    def __init__(self, api, profile, *, shell_asset, read_context, startup, process=None):
        fields(shell_asset,('container_id','image_id','path','sha256'),'qualified image-build shell asset')
        require(shell_asset['container_id']==profile['actor']['container_id']
                and shell_asset['image_id']==profile['actor']['image_id']
                and shell_asset['path']=='/usr/bin/dash' and digest(shell_asset['sha256'])
                and callable(read_context) and callable(startup), 'explicit original shell asset and generation provider required')
        self.api,self.profile,self.shell=api,deepcopy(profile),deepcopy(shell_asset)
        self.read_context,self.startup=read_context,startup
        self.process=ImageBuildHealthcheckProcess() if process is None else process
        self.pins_sha256=fingerprint(dict(profile=self.profile,shell=self.shell))

    def _original(self, value):
        profile=self.profile
        require(fingerprint(dict(profile=profile,shell=self.shell))==self.pins_sha256
                and self.read_context()==profile['context'] and value['actor']==profile['actor'],
                'original image-build healthcheck owner/context differs')
        capture,generation=profile['capture'],profile['generation']
        start=value.get('actions',{}).get('start')
        if start is not None:
            proof=self.startup(deepcopy(value))
            ImageBuildCommands._start_proof(proof,start['command'],start['reference'])
            capture,generation=proof['capture'],proof['generation']
        inspected=self.api.inspect(profile['actor']['container_id'])
        require(inspected is not None and inspected.get('Id')==profile['actor']['container_id']
                and inspected.get('Image')==profile['actor']['image_id'], 'original healthcheck container differs')
        normalized=deepcopy(inspected);normalized['HostConfig']['RestartPolicy']=profile['policy']
        require(config_digest(normalized)==profile['actor']['config_sha256']
                and inspected['Config'].get('Healthcheck',{}).get('Test')==TEST
                and inspected['Config'].get('User','') in ('','0','root','0:0','root:root')
                and inspected['HostConfig']['RestartPolicy'] in (profile['policy'],NO_RESTART)
                and inspected['State']['Running'] is True and inspected['State']['Status']=='running'
                and inspected['State']['Pid']==capture['process']['pid']
                and inspected['State']['StartedAt']==generation['started_at']
                and inspected['RestartCount']==generation['restart_count']
                and not inspected['State'].get('OOMKilled') and not inspected['State'].get('Error')
                and {name:row['NetworkID'] for name,row in inspected['NetworkSettings']['Networks'].items()}==profile['networks'],
                'original configured healthcheck generation differs')
        return capture,generation,inspected

    def _assets(self, captured, main, kind):
        view=captured['process'];profile=self.profile
        executable=self.shell if kind=='shell' else dict(path=profile['capture']['process']['exe'],sha256=profile['capture']['executable']['sha256'])
        require(view['exe']==executable['path'] and captured['executable']['sha256']==executable['sha256']
                and all(view[key]==main['process'][key] for key in ('cwd','import_env_sha256','namespaces','cgroup'))
                and view['credentials']==dict(uid=0,gid=0)
                and view['user_namespace']==profile['context']['namespaces']['user']
                and set(captured['sources'])==set(profile['copies'])
                and all(captured['sources'][path]['sha256']==sha for path,sha in profile['copies'].items()),
                'healthcheck interpreter/shell, environment or namespace/artifact differs')

    def __call__(self, value, inspected, rows):
        expected,generation,before=self._original(value)
        require(stable_inspect(before)==stable_inspect(inspected) and type(rows) is list and 2<=len(rows)<=3
                and len({row['pid'] for row in rows})==len(rows), 'original bounded healthcheck census required')
        for row in rows:
            fields(row,('pid','start_ticks','command_sha256','cgroup_sha256','container','reason'),'healthcheck census process')
            require(type(row['pid']) is int and row['pid']>0 and row['container'] is True and row['reason'] is None,
                    'only original container API and healthcheck processes eligible')
        primary=[row for row in rows if row['pid']==expected['process']['pid']]
        require(len(primary)==1, 'original primary API absent from healthcheck census')
        extra=[row for row in rows if row not in primary];kinds={};captures={}
        for row in extra:
            names=[kind for kind,sha in HASHES.items() if sha==row['command_sha256']]
            require(len(names)==1 and names[0] not in kinds, 'only one exact configured shell/Python healthcheck eligible')
            kinds[names[0]]=row
        with ExitStack() as stack:
            main=stack.enter_context(self.process.capture(expected['process']['pid'],self.profile['actor']['container_id'],self.profile['copies']))
            require(all(main['process'].get(key)==item for key,item in expected['process'].items())
                    and main['sources']==expected['sources'] and main['executable']==expected['executable'],
                    'original API process/source changed during healthcheck qualification')
            stable=lambda row:{key:item for key,item in row.items() if key not in ('pid','start_ticks','namespaces')}
            require(stable(expected['process'])==stable(self.profile['capture']['process'])
                    and primary[0]['start_ticks']==main['process']['start_ticks']
                    and primary[0]['command_sha256']==main['process']['cmdline_sha256']
                    and primary[0]['cgroup_sha256']==hashlib.sha256(main['process']['cgroup'].encode()).hexdigest(),
                    'original API invocation or census identity differs')
            self._assets(main,main,'python')
            for kind,row in kinds.items():
                capture=stack.enter_context(self.process.capture(row['pid'],self.profile['actor']['container_id'],self.profile['copies']))
                self._assets(capture,main,kind);view=capture['process']
                require(view['pid']==row['pid'] and view['start_ticks']==row['start_ticks']
                        and view['cmdline_sha256']==row['command_sha256']==HASHES[kind]
                        and hashlib.sha256(view['cgroup'].encode()).hexdigest()==row['cgroup_sha256']
                        and int(view['start_ticks'])>=int(main['process']['start_ticks']),
                        'original healthcheck process generation differs')
                captures[kind]=capture
            require('shell' not in kinds or 'python' not in kinds
                    or captures['python']['process']['parent_pid']==kinds['shell']['pid'],
                    'observed healthcheck shell/Python relationship differs')
            after_capture,after_generation,after=self._original(value)
            require(after_capture==expected and after_generation==generation and stable_inspect(after)==stable_inspect(before),
                    'original API changed during healthcheck qualification')
            proof=dict(kind=KIND,container_id=before['Id'],image_id=before['Image'],config_sha256=config_digest(before),
                generation_sha256=fingerprint(dict(capture=expected,generation=generation)),main_process=deepcopy(primary[0]),
                processes=deepcopy(extra),evidence_sha256=fingerprint(dict(main=main,healthchecks=captures)))
        self._original(value)
        return proof
