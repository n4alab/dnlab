"""Connect VM controllers through the original dedicated daemon receipts.

The caller retains the original activation journal, root and process pins for
the whole attempt. Native unit/socket readers and SDK provenance are qualified
by that caller. This adapter neither installs services nor imports libvirt,
opens an SDK connection during construction, or discovers domains by name.
"""
from contextlib import contextmanager
from copy import deepcopy
import os
import stat

from dnlab_runtime.libvirt_activation import SessionActivation, steps
from dnlab_runtime.libvirt_session import DedicatedSession
from dnlab_runtime.manifest import fingerprint, identifier
from dnlab_runtime.vm_template import digest, require
from tools.libvirt_service_generation import NativeServiceObserver, directory_identity
from tools.vm_host_inventory import entry


class NativeVMSession:
    def __init__(self, *, activation_id, activation_sha256, read_activation,
                 root, pins, unit_reader, socket_reader, verify_source):
        identifier(activation_id, 'original dedicated activation')
        require(digest(activation_sha256)
                and all(callable(fn) for fn in (read_activation, unit_reader, verify_source))
                and all(callable(getattr(pins, name, None)) for name in ('pin', 'observe'))
                and callable(socket_reader) and callable(getattr(socket_reader, 'pin', None)),
                'original dedicated service and source observation providers required')
        self.activation_id, self.activation_sha256 = activation_id, activation_sha256
        self.read_activation, self.verify_source = read_activation, verify_source
        self.root, self.pins, self.sockets = root, pins, socket_reader
        info = os.fstat(root)
        require(stat.S_ISDIR(info.st_mode), 'original open session root required')
        self.root_identity = (info.st_dev, info.st_ino)
        original = self._activation()
        self.source = deepcopy(original['installation'])
        self.source_sha256 = fingerprint(self.source)
        self._source()
        self.observer = NativeServiceObserver(self.source, unit_reader=unit_reader,
                                              processes=pins, socket_reader=socket_reader)
        self.witnesses = {}
        for item in original['items']:
            if item['spec']['kind'] != 'start':
                continue
            service = item['proof']['identity']['service']
            request = dict(spec=deepcopy(item['spec']), context=deepcopy(self.source['context']),
                           installation_sha256=self.source_sha256)
            subscription = dict(request_sha256=fingerprint(request),
                                context_sha256=fingerprint(request['context']))
            reference = pins.pin(request, subscription, service['process']['pid'],
                                 service['unit']['invocation_id'])
            invocation = dict(pid=reference['pid'], invocation_id=reference['invocation_id'],
                              process_reference=deepcopy(reference))
            self.witnesses[item['spec']['role']] = (request, invocation, deepcopy(service))
        self.witnesses_sha256 = fingerprint(self.witnesses)
        self.check()
        self.session = DedicatedSession(self.source['profile']['session'], self.proof)

    def _activation(self):
        value = self.read_activation(self.activation_id)
        require(fingerprint(value) == self.activation_sha256
                and value['id'] == self.activation_id and value['phase'] == 'ready_empty'
                and value['installation_sha256'] == fingerprint(value['installation']),
                'original completed dedicated activation changed')
        expected = steps(value['installation']['profile'])
        require(len(value['items']) == len(expected), 'complete original activation steps required')
        for item, spec in zip(value['items'], expected):
            require(item['spec'] == spec and item['phase'] == 'confirmed',
                    'all original dedicated start receipts required')
            SessionActivation._receipt(value, item, item['proof'])
        require(value['empty_proof'] == dict(
            installation_sha256=value['installation_sha256'], domains=[],
            service_proofs_sha256=fingerprint([item['proof'] for item in value['items']])),
            'original completed empty-session receipt required')
        return value

    def _source(self):
        info = os.fstat(self.root)
        require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.root_identity
                and fingerprint(self.source) == self.source_sha256
                and self._activation()['installation'] == self.source
                and self.verify_source(deepcopy(self.source)) == self.source_sha256,
                'original native VM session source or context changed')

    def check(self):
        self._source()
        require(fingerprint(self.witnesses) == self.witnesses_sha256
                and set(self.witnesses) == {'virtlogd', 'virtlockd', 'libvirtd'},
                'all original dedicated daemon witnesses required')
        processes = {}
        for request, invocation, original in self.witnesses.values():
            current = self.observer(deepcopy(request), deepcopy(invocation))
            require(current == original, 'original dedicated daemon generation changed')
            processes[request['spec']['unit']] = deepcopy(current['process'])
        require(len({value['pid'] for value in processes.values()}) == 3,
                'distinct original dedicated daemon processes required')
        self._source()
        return processes

    def services(self):
        """Fresh original process observations for SessionWriterCensus."""
        return self.check()

    def proof(self):
        self.check()
        session = self.source['profile']['session']
        directories = {}
        for label, key in (('state', 'state_root'), ('runtime', 'runtime_root')):
            path = session[key]
            matches = [item for item in self.source['items']
                       if item['spec'].get('kind') == 'directory' and item['spec'].get('path') == path]
            require(len(matches) == 1 and matches[0]['phase'] == 'created',
                    'original dedicated directory receipt required')
            with entry(self.root, path.lstrip('/')) as (_, _, info):
                require(directory_identity(info) == matches[0]['proof']['identity'],
                        'original dedicated session directory changed')
                directories[label] = dict(device=info.st_dev, inode=info.st_ino,
                    uid=info.st_uid, gid=info.st_gid, mode=info.st_mode)
        service = self.witnesses['libvirtd'][2]
        process = service['process']
        value = dict(profile_sha256=fingerprint(session),
            config_sha256=fingerprint(self.source['profile']['files']),
            daemon=dict(uid=process['uids'][0], gid=process['gids'][0],
                boot_id=process['boot_id'], pid=process['pid'], start_ticks=process['start_ticks'],
                executable_sha256=process['executable_sha256']),
            socket={key:service['socket'][key] for key in ('device', 'inode', 'uid', 'gid', 'mode')},
            directories=directories)
        self.check()
        return value

    @contextmanager
    def pin_socket(self, original):
        require(self.session.proof() == original, 'original dedicated SDK session proof changed')
        request, _, service = self.witnesses['libvirtd']
        with self.sockets.pin(request['spec'], service['process']['pid']) as pair:
            require(pair[1] == service['socket'], 'original libvirt SDK socket changed')
            self.check()
            try:
                yield pair
            finally:
                self.check()

    @contextmanager
    def connect(self, *, sdk, readonly, event_loop=None):
        """SDK/module and event-loop provenance remain the caller's obligation."""
        from dnlab_runtime.libvirt_sdk import open_connection
        require(type(readonly) is bool, 'explicit readonly or VM writer connection required')
        self.check()
        with open_connection(self.session, pin_socket=self.pin_socket, readonly=readonly,
                             sdk=sdk, event_loop=event_loop) as connection:
            try:
                yield connection
            finally:
                self.check()
