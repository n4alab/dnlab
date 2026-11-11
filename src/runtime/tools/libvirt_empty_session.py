"""Qualify the all-domain inventory of the original dedicated libvirtd."""

from copy import deepcopy
import subprocess
from urllib.parse import urlencode

from dnlab_runtime.libvirt_account_runner import open_resource
from dnlab_runtime.libvirt_account_worker import binary_proof
from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import digest


class EmptySessionInventory:
    def __init__(self, installation, *, binary, sockets, read_generation,
                 opener=open_resource, run=subprocess.run):
        if (set(binary) != {'path', 'sha256'} or binary['path'] != '/usr/bin/virsh'
                or not digest(binary['sha256'])):
            raise Conflict('original virsh binary proof required')
        self.installation = deepcopy(installation)
        self.binary = deepcopy(binary)
        self.sockets, self.read_generation = sockets, read_generation
        self.opener, self.run = opener, run

    def __call__(self, value, receipts):
        source = self.installation
        expected = fingerprint(source)
        if (value['installation'] != source or value['installation_sha256'] != expected
                or [item['spec'] for item in value['items']] != steps(source['profile'])
                or set(receipts) != {item['spec']['key'] for item in value['items']}
                or any(item['phase'] != 'confirmed' or not item['proof']
                       or receipts[item['spec']['key']] != item['proof'] for item in value['items'])):
            raise Conflict('confirmed activation required before listing dedicated domains')
        item = next(item for item in value['items'] if item['spec'].get('role') == 'libvirtd')
        read = self.read_generation(value, item, item['proof'])
        original = item['proof']['identity']['service']
        if read() != original:
            raise Conflict('original libvirtd generation differs before domain query')
        profile = source['profile']
        environment = dict(profile['client_environment'], HOME=profile['session']['state_root'],
                           PATH='/usr/bin:/bin', LC_ALL='C', LANG='C')
        with (self.opener(self.binary['path']) as executable,
              self.sockets.pin(item['spec'], original['process']['pid']) as (socket_fd, endpoint)):
            binary_proof(executable, self.binary['sha256'])
            if endpoint != original['socket']:
                raise Conflict('original libvirtd socket differs before domain query')
            uri = 'qemu+unix:///session?' + urlencode(
                dict(socket=f'/proc/self/fd/{socket_fd}', mode='legacy'))
            argv = [self.binary['path'], '--readonly', '--quiet', '--connect', uri,
                    'list', '--all', '--uuid']
            try:
                response = self.run(argv, executable=f'/proc/self/fd/{executable}',
                                    pass_fds=(executable, socket_fd), stdin=subprocess.DEVNULL,
                                    capture_output=True, env=environment, cwd='/', timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise Conflict('readonly dedicated domain query failed') from error
            if response.returncode != 0 or response.stderr != b'' or response.stdout != b'':
                raise Conflict('readonly dedicated domain query did not prove an empty session')
        if read() != original:
            raise Conflict('original libvirtd generation differs after domain query')
        return dict(installation_sha256=expected, domains=[],
                    service_proofs_sha256=fingerprint([item['proof'] for item in value['items']]))
