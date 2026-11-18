"""Payload and phase-specific guards for a dedicated image-build canary.

No container is created here. NosFixture supplies durable intent/nonce/ID before
use; the hold session supplies service operations. Paths must be independently
qualified private directories before this payload is submitted to Docker.
"""
from copy import deepcopy
from pathlib import PurePosixPath

from dnlab_runtime.backend import LABEL, labels
from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.libvirt_xml import absolute
from dnlab_runtime.vm_template import digest, require

POLICY=dict(Name='unless-stopped',MaximumRetryCount=0)


def payload(image, nonce, *, checkout, workspace, logs):
    require(type(nonce) is str and len(nonce)==32 and digest(nonce*2)
            and type(image) is dict and type(image.get('Id')) is str and image['Id'].startswith('sha256:')
            and digest(image['Id'][7:]), 'original local image and canary nonce required')
    for path in (checkout,workspace,logs):absolute(path)
    paths=[PurePosixPath(path) for path in (checkout,workspace,logs)]
    require(all(':' not in str(path) for path in paths)
            and all(not left.is_relative_to(right) and not right.is_relative_to(left)
                    for index,left in enumerate(paths) for right in paths[index+1:]),
            'separate readonly checkout and private writable paths required')
    require(set(image['Config'].get('Volumes') or {})=={'/opt/vrnetlab','/var/lib/dnlab-image-build'},
            'original declared image volumes required; no anonymous volumes')
    name='drsp-ibc-'+nonce[:12]
    request=dict(lab_id=name,node_id='image-build')
    spec=dict(kind='linux',image=image['Id'],container_name=name,stop_timeout=30)
    inherited=deepcopy(image['Config'].get('Labels') or {})
    require(not any(key.startswith(LABEL) for key in inherited), 'image must not inherit a runtime owner')
    inherited={key:('' if key.startswith('com.docker.compose.') else value) for key,value in inherited.items()}
    inherited.update(labels(request,spec));inherited.update({'io.dnlab.spike':'image-build-hold','io.dnlab.lab':name})
    replacements=dict(DNLAB_IMAGE_BUILD_WORKSPACE='/var/lib/dnlab-image-build',DNLAB_LOG_ROOT='/var/log/dnlab',
                      DNLAB_VRNETLAB_DIR='/opt/vrnetlab',DNLAB_IMAGE_BUILD_API_HOST='127.0.0.1',
                      DNLAB_IMAGE_BUILD_API_PORT='8082',DNLAB_IMAGE_BUILD_API_RELOAD='false',PYTHONDONTWRITEBYTECODE='1')
    env=[];seen=set()
    for item in image['Config'].get('Env') or []:
        key,separator,_=item.partition('=')
        require(separator and key not in seen, 'unique original image environment required');seen.add(key)
        if key not in replacements:env.append(item)
    env.extend(key+'='+value for key,value in replacements.items())
    config=dict(Image=image['Id'],Entrypoint=None,Cmd=['python','/opt/dnlab-image-build/api.py'],
        WorkingDir='/opt/dnlab-image-build',User='0:0',Env=env,Labels=inherited,Tty=False,
        Healthcheck={'Test':['NONE']},StopTimeout=30,HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,
            CapDrop=['ALL'],CapAdd=[],Privileged=False,PidMode='',IpcMode='private',UTSMode='',UsernsMode='',
            SecurityOpt=['no-new-privileges:true'],RestartPolicy=deepcopy(POLICY),PidsLimit=128,Memory=536870912,
            NanoCpus=500000000,PortBindings={},PublishAllPorts=False,
            Binds=[checkout+':/opt/vrnetlab:ro',workspace+':/var/lib/dnlab-image-build:rw',logs+':/var/log/dnlab:rw'],
            LogConfig={'Type':'json-file','Config':{'max-size':'1m','max-file':'1'}}))
    return dict(request=request,spec=spec,config=config)


def qualify(current, *, container_id, name, effective_config, phase, restart_policy):
    require(all(type(effective_config['Labels'].get(LABEL+suffix)) is str
                and len(effective_config['Labels'][LABEL+suffix])==32
                and digest(effective_config['Labels'][LABEL+suffix]*2) for suffix in ('.creator','.birth')),
            'original durable fixture birth labels required')
    require(phase in ('created','running','exited') and restart_policy in (POLICY,NO_RESTART),
            'original explicit canary lifecycle/policy required')
    require(type(current) is dict and current.get('Id')==container_id and current.get('Name')=='/'+name
            and current.get('Image')==effective_config['Image'] and current['State']['Status']==phase,
            'original canary identity/lifecycle differs')
    config=current['Config'];host=current['HostConfig'];expected=effective_config['HostConfig']
    for key in ('Entrypoint','Cmd','WorkingDir','User','Env','Labels','Tty'):
        require(config.get(key)==effective_config[key], 'original canary config differs: '+key)
    require(config.get('Healthcheck',{}).get('Test')==['NONE']
            and not any(value for key,value in config['Labels'].items() if key.startswith('com.docker.compose.')),
            'canary healthcheck or production Compose role differs')
    for key in ('NetworkMode','ReadonlyRootfs','CapDrop','Privileged','PidMode','IpcMode','UTSMode','UsernsMode',
                'SecurityOpt','PidsLimit','Memory','NanoCpus','PublishAllPorts'):
        require(host.get(key)==expected[key], 'original canary isolation differs: '+key)
    require(host.get('RestartPolicy')==restart_policy and not host.get('CapAdd') and not host.get('Devices')
            and not host.get('VolumesFrom') and not host.get('PortBindings') and not host.get('Tmpfs'),
            'unexpected canary host privileges, mounts or policy')
    require(sorted(host.get('Binds') or [])==sorted(expected['Binds']), 'original private canary binds differ')
    mounts=current.get('Mounts');wanted=[]
    for item in expected['Binds']:
        source,destination,mode=item.rsplit(':',2);wanted.append(('bind',source,destination,mode=='rw'))
    require(type(mounts) is list, 'canary mounts missing')
    actual=[(row.get('Type'),row.get('Source'),row.get('Destination'),row.get('RW')) for row in mounts]
    require((not actual and phase!='running') or sorted(actual)==sorted(wanted), 'original realized canary mounts differ')
    require(not current['State'].get('OOMKilled') and not current['State'].get('Error'), 'canary lifecycle error')
    return True
