"""Open a verified system-bus connection and identify its systemd manager."""

from contextlib import contextmanager
import ctypes as C
import os
import re
import socket
import struct
from time import monotonic

from dnlab_runtime.vm_bundle import pinned_file
from tools.libvirt_bus_prerequisites import LIBRARY, PARENTS, SOCKET, hash_library, library_path
from tools.libvirt_systemd_bus import SdBusABI, require, success
from tools.vm_host_inventory import probe


BROKER = 'org.freedesktop.DBus'
MANAGER = 'org.freedesktop.systemd1'
TIMEOUT = 5


def unique_name(value):
    return isinstance(value, str) and re.fullmatch(r':[0-9]+\.[0-9]+', value) is not None


class ConnectionABI(SdBusABI):
    def __init__(self, library):
        super().__init__(library)
        pointer = C.c_void_p
        signatures = {
            'sd_bus_new': ([C.POINTER(pointer)], C.c_int),
            'sd_bus_set_fd': ([pointer, C.c_int, C.c_int], C.c_int),
            'sd_bus_set_bus_client': ([pointer, C.c_int], C.c_int),
            'sd_bus_start': ([pointer], C.c_int),
            'sd_bus_process': ([pointer, C.POINTER(pointer)], C.c_int),
            'sd_bus_wait': ([pointer, C.c_uint64], C.c_int),
            'sd_bus_unref': ([pointer], pointer),
        }
        for name, (arguments, result) in signatures.items():
            call = getattr(library, name)
            call.argtypes = arguments
            call.restype = result

    @contextmanager
    def connected_socket(self, stream, *, deadline):
        handle = C.c_void_p()
        descriptor = None
        library = self.library
        try:
            success(library.sd_bus_new(C.byref(handle)), 'sd_bus_new')
            require(handle.value is not None, 'new bus handle missing')
            descriptor = os.dup(stream.fileno())
            success(library.sd_bus_set_fd(handle, descriptor, descriptor), 'sd_bus_set_fd')
            descriptor = None  # The bus now owns the duplicate.
            success(library.sd_bus_set_bus_client(handle, 1), 'sd_bus_set_bus_client')
            success(library.sd_bus_start(handle), 'sd_bus_start')
            while not success(library.sd_bus_is_ready(handle), 'sd_bus_is_ready'):
                remaining = self._remaining(deadline)
                if not success(library.sd_bus_process(handle, None), 'sd_bus_process'):
                    success(library.sd_bus_wait(handle, remaining), 'sd_bus_wait')
            self._remaining(deadline)
            yield handle
        finally:
            if handle.value is not None:
                library.sd_bus_unref(handle)
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _remaining(deadline):
        remaining = int((deadline - monotonic()) * 1_000_000)
        if remaining <= 0:
            raise TimeoutError('system bus connection proof timed out')
        return remaining

    def _broker_query(self, handle, method, argument, output, deadline):
        reply = self._call(handle, BROKER, '/org/freedesktop/DBus', BROKER,
                           method, [argument], output, self._remaining(deadline))
        require(reply['sender'] == BROKER and 0 < reply['call_serial'] == reply['reply_serial'],
                'system bus broker reply does not match its request')
        return reply['body'][0]

    def identity(self, handle, *, deadline):
        name = C.c_char_p()
        success(self.library.sd_bus_get_unique_name(handle, C.byref(name)), 'sd_bus_get_unique_name')
        client = name.value.decode('ascii') if name.value else None
        require(unique_name(client), 'unique system bus client name required')
        client_pid = self._broker_query(handle, 'GetConnectionUnixProcessID', client, 'u', deadline)
        require(client_pid == os.getpid(), 'system bus client PID differs')
        owner = self._broker_query(handle, 'GetNameOwner', MANAGER, 's', deadline)
        require(unique_name(owner) and owner != client, 'unique systemd manager owner required')
        pid = self._broker_query(handle, 'GetConnectionUnixProcessID', owner, 'u', deadline)
        uid = self._broker_query(handle, 'GetConnectionUnixUser', owner, 'u', deadline)
        require(pid == 1 and uid == 0,
                f'expected systemd manager PID 1 and UID 0, observed PID {pid} and UID {uid}')
        return dict(unique_name=client, manager_owner=owner, manager_pid=pid, manager_uid=uid)


def verify_paths(root, proof):
    for path in PARENTS:
        current = probe(root, path)
        expected = proof['parents'][path]
        # /run timestamps and sizes change independently of the socket.
        require(current['status'] == 'present' and current['kind'] == 'directory'
                and current['metadata'][:5] == expected['metadata'][:5]
                and current['metadata'][3] == 0 and not current['metadata'][2] & 0o022,
                'system bus inventory directory differs: ' + path)
    require(probe(root, SOCKET) == proof['socket'] and proof['socket']['kind'] == 'socket'
            and proof['socket']['metadata'][3] == 0, 'system bus socket identity differs')
    require(probe(root, LIBRARY) == proof['library']['alias'], 'systemd library alias differs')


def peer_credentials(stream):
    pid, uid, gid = struct.unpack('iII', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid > 0, 'system bus peer PID unavailable in the observed namespace')
    return dict(pid=pid, uid=uid, gid=gid)


@contextmanager
def open_proven_bus(root, inventory, *, read_context, load=C.CDLL, socket_factory=socket.socket):
    """Keep library, connection and original provenance in the owning process."""
    expected = inventory['context']
    proof = inventory['proof']
    require(read_context() == expected, 'system bus inventory context differs')
    verify_paths(root, proof)
    path = library_path(proof['library']['alias'])
    require(path == proof['library']['path'], 'systemd library target differs')
    with pinned_file(root, path) as (fd, info):
        require(hash_library(fd, info) == proof['library']['object'], 'systemd library digest or identity differs')
        # Load the exact bytes just hashed through the retained descriptor.
        library = load(f'/proc/self/fd/{fd}', mode=os.RTLD_NOW | os.RTLD_LOCAL)
        abi = ConnectionABI(library)
        with socket_factory(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(TIMEOUT)
            stream.connect('/' + SOCKET)
            peer = peer_credentials(stream)
            verify_paths(root, proof)
            deadline = monotonic() + TIMEOUT
            with abi.connected_socket(stream, deadline=deadline) as handle:
                identity = abi.identity(handle, deadline=deadline)
                yield abi, handle, dict(identity, peer=peer)
                require(abi.identity(handle, deadline=monotonic() + TIMEOUT) == identity
                        and peer_credentials(stream) == peer, 'system bus connection identity changed')
                verify_paths(root, proof)
                require(read_context() == expected, 'system bus context changed')
