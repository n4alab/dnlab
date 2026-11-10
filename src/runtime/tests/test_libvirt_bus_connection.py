"""Exercise the readonly wrapper and sd-bus ownership using ABI doubles."""

import errno
import json
import os
import struct

import pytest

from tools.libvirt_bus_connection import open_proven_bus
from tools.libvirt_bus_connection_host import SCOPE, freeze, run
from tools.libvirt_bus_inventory_host import sha
from test_libvirt_bus_prerequisites import inventory, run as collect_fixture


class Library:
    def __init__(self, *, change_owner=False, fail_set_fd=False):
        self.functions = {}
        self.methods = []
        self.owner_reads = 0
        self.change_owner = change_owner
        self.fail_set_fd = fail_set_fd
        self.descriptor = None
        self.released = False

    def __getattr__(self, name):
        if name not in self.functions:
            def call(*args):
                return self.invoke(name, args)
            self.functions[name] = call
        return self.functions[name]

    def invoke(self, name, args):
        if name == 'sd_bus_new':
            args[0]._obj.value = 0x100
        elif name == 'sd_bus_set_fd':
            self.descriptor = args[1]
            assert args[2] == args[1]
            if self.fail_set_fd:
                return -errno.EBADF
        elif name in ('sd_bus_start', 'sd_bus_set_bus_client'):
            pass
        elif name == 'sd_bus_is_ready':
            return 1
        elif name == 'sd_bus_unref':
            self.released = True
            if not self.fail_set_fd:
                os.close(self.descriptor)
            return None
        elif name == 'sd_bus_get_unique_name':
            args[1]._obj.value = b':1.43'
        elif name == 'sd_bus_message_new_method_call':
            assert args[2:5] == (b'org.freedesktop.DBus', b'/org/freedesktop/DBus', b'org.freedesktop.DBus')
            self.methods.append(args[5].decode())
            args[1]._obj.value = 0x200
        elif name == 'sd_bus_message_append_basic':
            self.argument = args[2].value
        elif name == 'sd_bus_call':
            assert 0 < args[2] <= 5_000_000
            args[4]._obj.value = 0x300
        elif name in ('sd_bus_message_get_cookie', 'sd_bus_message_get_reply_cookie'):
            args[1]._obj.value = 17
        elif name == 'sd_bus_message_get_sender':
            return b'org.freedesktop.DBus'
        elif name == 'sd_bus_message_get_signature':
            return b's' if self.methods[-1] == 'GetNameOwner' else b'u'
        elif name == 'sd_bus_message_read_basic':
            if self.methods[-1] == 'GetNameOwner':
                self.owner_reads += 1
                args[2]._obj.value = b':1.44' if self.change_owner and self.owner_reads == 2 else b':1.1'
            elif self.methods[-1] == 'GetConnectionUnixProcessID':
                args[2]._obj.value = os.getpid() if self.argument == b':1.43' else 1
            elif self.methods[-1] == 'GetConnectionUnixUser':
                args[2]._obj.value = 0
            else:
                pytest.fail('unexpected broker query')
            return 1
        elif name == 'sd_bus_message_unref':
            return None
        else:
            pytest.fail('unexpected ABI call ' + name)
        return 0


class Stream:
    def __init__(self):
        self.fd, self.writer = os.pipe()
        self.connected = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)
        os.close(self.writer)

    def fileno(self):
        return self.fd

    def settimeout(self, timeout):
        assert timeout == 5

    def connect(self, path):
        assert path == '/run/dbus/system_bus_socket' and not self.connected
        self.connected = True

    def getsockopt(self, *_):
        assert self.connected
        return struct.pack('iII', 42, 102, 102)


@pytest.fixture
def inputs(inventory, tmp_path):
    report = collect_fixture(inventory)
    raw = json.dumps(report, sort_keys=True).encode()
    recipe = tmp_path / 'connection-recipe'
    freeze(recipe, dict(nonce='3' * 32, host_id='synthetic', scope=SCOPE, inventory_sha256=sha(raw)))
    output = tmp_path / 'connection-reports'
    output.mkdir(mode=0o700)
    return recipe, raw, output


@pytest.mark.parametrize('fault', [None, 'changed-owner', 'set-fd', 'socket', 'library'])
def test_connection_report_and_owned_descriptor_cleanup(inventory, inputs, fault):
    recipe, raw, output = inputs
    root, context, _, _, target, socket_stat = inventory
    library = Library(change_owner=fault == 'changed-owner', fail_set_fd=fault == 'set-fd')
    loads = []

    def load(path, *, mode):
        assert path.startswith('/proc/self/fd/') and mode & os.RTLD_NOW
        loads.append(path)
        return library

    def opener(*args, **kwargs):
        return open_proven_bus(*args, **kwargs, load=load, socket_factory=lambda *_: Stream())

    if fault == 'socket':
        socket_stat.st_ino += 1
    if fault == 'library':
        target.write_bytes(b'\x7fELFchanged')
    result, path = run(recipe, raw, root_fd=root, read_context=lambda: context,
                       output_parent=output, opener=opener)
    assert json.loads((path / 'result.json').read_bytes()) == result
    if fault in ('socket', 'library'):
        assert result['status'] == 'failed' and loads == []
    else:
        assert library.released and len(loads) == 1
        with pytest.raises(OSError):
            os.fstat(library.descriptor)
        if fault is None:
            assert result['status'] == 'verified'
            assert result['connection']['manager_pid'] == 1
            assert result['connection']['peer']['uid'] == 102
        else:
            assert result['status'] == 'failed'
    assert len(library.methods) == (8 if fault in (None, 'changed-owner') else 0)


def test_inventory_digest_mismatch_precedes_context_and_connection(inventory, inputs):
    recipe, raw, output = inputs
    with pytest.raises(ValueError, match='inventory digest differs'):
        run(recipe, raw + b' ', root_fd=inventory[0], read_context=lambda: pytest.fail('context accessed'),
            output_parent=output, opener=lambda *_: pytest.fail('connection opened'))
    assert list(output.iterdir()) == []
