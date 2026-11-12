"""Official Python SDK bound to one qualified dedicated daemon/socket.

No default connection, URI alias, credentials, reconnect or retry is used.
The connection and domain handles expire together. Domain ownership, operation
intents, event continuity and disk/endpoint admission remain upper-layer checks.
"""
from contextlib import contextmanager
from copy import deepcopy
import os
import stat
from urllib.parse import urlencode
import weakref
from xml.etree import ElementTree as ET

from .manifest import Conflict, fingerprint, identifier
from .vm_template import fields, require
from .workload_identity import WorkloadReference


def _socket_identity(fd):
    info = os.fstat(fd)
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid, mode=info.st_mode)


class Domain:
    def __init__(self, connection, raw, uuid):
        WorkloadReference('libvirt', 'vm', uuid)
        self._connection, self._raw, self._uuid = connection, raw, uuid
        connection._domains.add(self)

    def _call(self, method, *args, mutate=False):
        require(self._raw is not None, 'original libvirt domain handle expired')
        return self._connection._call(self._raw, method, *args, mutate=mutate, uuid=self._uuid)

    def UUIDString(self):return self._call('UUIDString')
    def name(self):return self._call('name')
    def isActive(self):return self._call('isActive')
    def isPersistent(self):return self._call('isPersistent')

    def XMLDesc(self, flags=0):
        require(type(flags) is int and flags in (0, 2), 'qualified VM XML flags required')
        return self._call('XMLDesc', flags)

    def state(self, flags=0):
        require(type(flags) is int and flags == 0, 'qualified VM state flags required')
        return self._call('state', flags)

    def hasManagedSaveImage(self, flags=0):
        require(type(flags) is int and flags == 0, 'qualified VM managed-save flags required')
        return self._call('hasManagedSaveImage', flags)

    def createWithFlags(self, flags):
        require(type(flags) is int and flags == 1, 'initial VM start must pause CPUs')
        return self._call('createWithFlags', flags, mutate=True)

    def resume(self):return self._call('resume', mutate=True)


class Connection:
    def __init__(self, session, original, socket_fd, raw, readonly, transport_uri):
        self._session, self._original, self._fd = session, deepcopy(original), socket_fd
        self._raw, self._readonly, self._transport_uri = raw, readonly, transport_uri
        self._active, self._broken = True, False
        self._domains = weakref.WeakSet()

    def _check(self):
        require(self._active and not self._broken and self._raw is not None, 'original libvirt connection unavailable')
        try:
            self._session.verify(fingerprint(self._original))
            require(_socket_identity(self._fd) == self._original['socket'], 'original libvirt socket FD changed')
            require(self._raw.isAlive() == 1 and self._raw.getURI() == self._transport_uri,
                    'original libvirt connection/URI differs')
        except Exception:
            self._broken = True
            raise
        return self._session.profile['uri']

    def _call(self, target, method, *args, mutate=False, uuid=None):
        if mutate and self._readonly:raise Conflict('readonly libvirt connection cannot mutate')
        self._check()
        if uuid is not None and target.UUIDString() != uuid:raise Conflict('original libvirt domain UUID differs')
        try:result = getattr(target, method)(*args)
        except Exception as error:
            try:self._check()
            except Exception:raise Conflict('libvirt session changed during failed call; outcome uncertain') from error
            raise
        self._check()
        if uuid is not None and target.UUIDString() != uuid:raise Conflict('original libvirt domain UUID changed during call')
        return result

    def getURI(self):return self._check()
    def getType(self):return self._call(self._raw, 'getType')
    def getLibVersion(self):return self._call(self._raw, 'getLibVersion')
    def getCapabilities(self):return self._call(self._raw, 'getCapabilities')

    def listAllDomains(self, flags=0):
        require(type(flags) is int and flags == 0, 'complete dedicated-domain inventory required')
        values = self._call(self._raw, 'listAllDomains', flags)
        return [Domain(self, raw, self._call(raw, 'UUIDString')) for raw in values]

    def lookupByUUIDString(self, uuid):
        WorkloadReference('libvirt', 'vm', uuid)
        raw = self._call(self._raw, 'lookupByUUIDString', uuid)
        require(self._call(raw, 'UUIDString') == uuid, 'libvirt lookup returned another UUID')
        return Domain(self, raw, uuid)

    def lookupByName(self, name):
        # Used by definition admission to reject an occupied name, never as a
        # fallback when the original UUID is missing.
        identifier(name, 'domain name')
        raw = self._call(self._raw, 'lookupByName', name)
        return Domain(self, raw, self._call(raw, 'UUIDString'))

    def defineXMLFlags(self, xml, flags):
        require(type(flags) is int and flags == 1, 'validated VM definition flag required')
        require(isinstance(xml, str) and 0 < len(xml.encode()) <= 1024 * 1024
                and '<!DOCTYPE' not in xml.upper() and '<!ENTITY' not in xml.upper(), 'bounded VM definition XML required')
        root = ET.fromstring(xml)
        require(root.tag == 'domain' and root.get('type') == 'kvm' and len(root.findall('uuid')) == 1,
                'single KVM domain UUID required')
        uuid = root.findtext('uuid');WorkloadReference('libvirt', 'vm', uuid)
        raw = self._call(self._raw, 'defineXMLFlags', xml, flags, mutate=True)
        require(self._call(raw, 'UUIDString') == uuid, 'libvirt definition returned another UUID; recover original call')
        return Domain(self, raw, uuid)

    def close(self):
        if not self._active:return
        self._active = False
        for domain in list(self._domains):domain._raw = None
        self._domains.clear()
        raw, self._raw = self._raw, None
        if raw is not None:raw.close()


@contextmanager
def open_connection(session, *, pin_socket, readonly=True, sdk=None):
    require(type(readonly) is bool and callable(pin_socket), 'explicit libvirt mode and socket provider required')
    require(os.environ.get('LIBVIRT_AUTOSTART') == '0', 'libvirt client autostart must be explicitly disabled')
    if sdk is None:
        try:import libvirt as sdk
        except ImportError as error:raise Conflict('official libvirt Python binding is not installed in this runtime') from error
    require(getattr(sdk, 'VIR_CONNECT_RO', None) == 1 and getattr(sdk, 'VIR_CONNECT_NO_ALIASES', None) == 2,
            'qualified libvirt open flags required')
    original = session.proof()
    with pin_socket(deepcopy(original)) as (fd, endpoint):
        fields(endpoint, ('path', 'device', 'inode', 'mode', 'uid', 'gid', 'peer_pid', 'peer_uid', 'peer_gid'), 'pinned SDK socket')
        require(type(fd) is int and fd >= 0 and endpoint['path'] == session.profile['socket']
                and {key:endpoint[key] for key in original['socket']} == original['socket']
                and endpoint['peer_pid'] == original['daemon']['pid']
                and endpoint['peer_uid'] == session.profile['uid'] and endpoint['peer_gid'] == session.profile['gid']
                and stat.S_ISSOCK(endpoint['mode']), 'SDK socket/peer differs from original daemon')
        session.verify(fingerprint(original))
        require(_socket_identity(fd) == original['socket'], 'original libvirt socket FD changed before connect')
        flags = sdk.VIR_CONNECT_NO_ALIASES | (sdk.VIR_CONNECT_RO if readonly else 0)
        uri = 'qemu+unix:///session?' + urlencode(dict(socket=f'/proc/self/fd/{fd}', mode='legacy'))
        raw = sdk.openAuth(uri, [[], lambda credentials, opaque: -1, None], flags)
        require(raw is not None, 'original libvirt SDK connection failed')
        connection = Connection(session, original, fd, raw, readonly, uri)
        try:
            connection._check()
            yield connection
        except BaseException as error:
            try:connection.close()
            except Exception as cleanup:error.add_note('libvirt close also failed: ' + str(cleanup))
            raise
        else:connection.close()
