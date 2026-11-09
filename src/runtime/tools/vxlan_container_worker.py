"""Owned Docker fixture jobs for the VXLAN packaging comparison.

The runtime core is provided by the pinned image. Only the test harness and
isolated fixture state are mounted; no Docker socket is given to the worker.
"""
import json
from pathlib import Path
import re
import subprocess
import uuid

from dnlab_runtime.backend import Docker
from dnlab_runtime.manifest import Conflict


LABEL = 'org.dnlab.runtime.fixture-worker'


def run_image_worker(path, config, *, docker=None, read_logs=None, harness='vxlan_crash_probe.py'):
    from vxlan_crash_probe import checkpoint
    image = config['executor_image']
    if not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise Conflict('fixture worker image must be an immutable local image ID')
    root = path.parent.resolve()
    prefixes={'vxlan_crash_probe.py':'dnlab-vxlan-traffic-', 'bridge_crash_probe.py':'dnlab-custom-bridge-'}
    if harness not in prefixes or root.parent != Path('/tmp') or not root.name.startswith(prefixes[harness]):
        raise Conflict('fixture Docker job requires its isolated /tmp directory')
    docker = docker or Docker()
    docker.request('GET', f'/images/{image}/json')  # No implicit image pull.
    token = uuid.uuid4().hex
    name = 'drsp-vxw-' + token[:12]
    tools = Path(__file__).resolve().parent
    identity = docker.create(name, {
        'Image': image, 'Env': ['DNLAB_RUNTIME_HOST_BOOT_ID_FILE=/run/dnlab-runtime/host-boot-id'],
        'Entrypoint': ['/usr/local/bin/python'],
        'Cmd': [str(tools/harness), '--execute', '--config', str(path)],
        'Labels': {LABEL: token, 'io.dnlab.spike': config['identity']['lab_id']},
        'HostConfig': {'NetworkMode': 'host', 'PidMode': 'host', 'Privileged': True,
                       'RestartPolicy': {'Name': 'no'}, 'AutoRemove': False,
                       'Binds': [f'{root}:{root}:rw', f'{tools}:{tools}:ro', '/var/run/netns:/var/run/netns:ro',
                                 '/proc/sys/kernel/random/boot_id:/run/dnlab-runtime/host-boot-id:ro']},
    })['Id']
    registry = root/'worker-containers.json'
    entries = json.loads(registry.read_text()) if registry.exists() else []
    entry = {'id': identity, 'name': name, 'token': token, 'image': image, 'phase': 'created'}
    entries.append(entry)
    checkpoint(registry, entries)

    def inspect():
        observed = docker.inspect(identity)
        if observed and (observed['Id'] != identity or observed['Config']['Labels'].get(LABEL) != token
                         or observed['Config']['Image'] != image):
            raise Conflict('fixture worker ownership/image changed; refusing cleanup')
        return observed

    try:
        inspect()
        docker.start(identity)
        status = docker.request('POST', f'/containers/{identity}/wait?condition=not-running')
        code = status['StatusCode']
        if read_logs is None:
            logs = subprocess.run(['docker', 'logs', identity], text=True, capture_output=True, timeout=10)
        else:
            logs = read_logs(identity)
        entry['exitcode'] = code
        entry['phase'] = 'exited'
        checkpoint(registry, entries)
        return subprocess.CompletedProcess(['image-worker', identity], code, logs.stdout, logs.stderr)
    finally:
        # A timed out wait never leaves a privileged job behind. SIGKILL is
        # explicit and applies only to this verified fixture process container.
        observed = inspect()
        if observed:
            if observed['State']['Running']:
                docker.signal(identity, 'SIGKILL')
                docker.request('POST', f'/containers/{identity}/wait?condition=not-running')
            docker.remove(identity)
        if inspect() is not None:
            raise Conflict('fixture worker removal incomplete')
        entry['phase'] = 'removed'
        checkpoint(registry, entries)
