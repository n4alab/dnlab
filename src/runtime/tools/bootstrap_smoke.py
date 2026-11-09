"""Isolated native fixture: patched launcher boot barrier and container restart."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/runtime'))
sys.path.insert(0, str(ROOT / 'src/image-build'))

from patches._common import patch_runtime_management
from dnlab_runtime.backend import Backend, labels
from dnlab_runtime.bootstrap import Bootstrap
from dnlab_runtime.journal import Journal
from dnlab_runtime.stable_management import Handoff, StablePort
from smoke import command, wait_for
from management_smoke import response

LAUNCHER = '''import os, re, time, signal, http.server
signal.signal(signal.SIGTERM, lambda *_: exit(0))
class VM:
    def __init__(self, mgmt_intf="eth0"):
        self.mgmt_intf = os.environ.get("CLAB_MGMT_INTF", mgmt_intf)
    def get_mgmt_address(self):
        return run_command(["ip", "--json", "address", "show", "dev", "eth0"])
VM()
with open('/proc/1/stat') as stream:
    boot = stream.read().rsplit(')', 1)[1].split()[19]
with open('/run/dnlab-runtime/guest-started', 'w') as stream:
    stream.write(boot)
http.server.HTTPServer(('0.0.0.0', 5000), http.server.SimpleHTTPRequestHandler).serve_forever()
'''


def run(image):
    token = 'btsp-' + uuid.uuid4().hex[:8]
    root = Path(tempfile.mkdtemp(prefix='dnlab-bootstrap-smoke-'))
    backend = Backend()
    journal = Journal(root / 'state')
    request = {'lab_id': token, 'node_id': 'fixture'}
    spec = {'kind': 'linux', 'image': '', 'container_name': 'dnlab-' + token, 'stop_timeout': 3}
    network = container_id = candidate_id = None
    tag = 'dnlab-bootstrap-spike:' + token
    report = {'scope': 'native Python patched constructor; not NOS qualification', 'checks': []}
    try:
        upstream = json.loads(command(['docker', 'image', 'inspect', image]))[0]
        digest = next((d for d in upstream.get('RepoDigests', []) if '@sha256:' in d), None)
        if not digest:
            raise RuntimeError('probe requires an existing digest-pinned base image')
        patched, ok = patch_runtime_management(LAUNCHER)
        assert ok
        (root / 'launcher.py').write_text(patched)
        (root / 'Dockerfile').write_text(f'FROM {digest}\nLABEL io.dnlab.spike="{token}"\nLABEL org.dnlab.capabilities="runtime-management-v1"\nLABEL org.dnlab.runtime-management.status="experimental-unqualified"\nLABEL org.dnlab.runtime-management.python="system"\nCOPY launcher.py /launcher.py\nENTRYPOINT ["python3", "/launcher.py"]\n')
        command(['docker', 'build', '-t', tag, str(root)])
        candidate_id = json.loads(command(['docker', 'image', 'inspect', tag]))[0]['Id']
        spec['image'] = candidate_id
        report['base_image_id'], report['candidate_image_id'] = upstream['Id'], candidate_id
        network_id = command(['docker', 'network', 'create', '--driver', 'bridge', '--label', 'io.dnlab.spike=' + token, 'dnlab-' + token])
        network = backend.docker.network(network_id)
        config = {'Image': candidate_id, 'Env': ['DNLAB_RUNTIME_BOOT_WAIT=true', 'DNLAB_RUNTIME_MGMT_INTF=mgmt0'], 'Labels': {**labels(request, spec), 'io.dnlab.spike': token}, 'HostConfig': {'NetworkMode': network['Name'], 'RestartPolicy': {'Name': 'no'}}}
        container_id = backend.docker.create(spec['container_name'], config)['Id']
        backend.docker.start(container_id)
        port = StablePort(backend, request, spec, '02:da:ab:00:00:02')
        handoff = Handoff(journal, backend, request, spec, port, spike_owner=token)
        gate = Bootstrap(backend, request, spec, port)
        # The exec assertion checks the same start token as the real patch. It
        # confirms that neither absence nor a persisted stale marker boots VM().
        blocked = "import os,time; time.sleep(.3); boot=open('/proc/1/stat').read().rsplit(')',1)[1].split()[19]; p='/run/dnlab-runtime/guest-started'; assert not os.path.exists(p) or open(p).read()!=boot"
        boots = []
        for cycle in range(2):
            backend.docker.exec_checked(container_id, ['python3', '-c', blocked])
            source = handoff.capture(network)
            identity = port.prepare(source)
            result = gate.release(identity, source)
            assert result['guest_readiness'] == 'unknown'
            ip = source['cidr'].split('/')[0]
            wait_for(lambda: response(f'http://{ip}:5000'))
            backend.docker.exec_checked(container_id, ['python3', '-c', "boot=open('/proc/1/stat').read().rsplit(')',1)[1].split()[19]; assert open('/run/dnlab-runtime/guest-started').read()==boot"])
            boots.append(identity)
            report['checks'].append('initial boot waits for verified setup' if cycle == 0 else 'persisted stale readiness marker cannot release restarted container')
            if cycle == 0:
                backend.stop(request, spec)
                backend.docker.start(container_id)
        assert boots[0]['started_at'] != boots[1]['started_at']
        report['boots'] = boots
        report['status'] = 'passed'
    finally:
        if container_id:
            backend.stop(request, spec, force=True)
            backend.remove(request, spec)
            assert backend.docker.inspect(container_id) is None
        if network:
            observed = backend.docker.network(network['Id'])
            assert observed['Labels'].get('io.dnlab.spike') == token and not observed.get('Containers')
            backend.docker.request('DELETE', '/networks/' + network['Id'])
        if candidate_id:
            observed = json.loads(command(['docker', 'image', 'inspect', candidate_id]))[0]
            assert observed['Config']['Labels'].get('io.dnlab.spike') == token
            command(['docker', 'image', 'rm', tag])
        journal.close()
        report['cleanup_verified'] = True
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'report': str(root / 'report.json'), **report}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--image', default='python:3.13-slim')
    args = parser.parse_args()
    if args.execute:
        run(args.image)
    else:
        print(json.dumps({'mutations_performed': False, 'creates': ['temporary native candidate image', 'isolated bridge', 'native fixture container'], 'checks': ['boot barrier', 'stable interface preparation', 'restart rejects stale marker', 'owned cleanup']}))
