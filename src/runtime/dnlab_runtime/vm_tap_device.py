"""Exclusive ephemeral TAP creation on one original namespace-bound TUN FD.

This primitive never persists a TAP, sets an owner, attaches a bridge, changes
addresses/routes, or hands its FD to QEMU. Closing the original FD disposes only
its ephemeral device. A persistent VM endpoint needs separate journal/worker,
configuration, handoff and cleanup protocols before using this primitive.

UAPI reference: Linux v6.12 include/uapi/linux/if_tun.h and drivers/net/tun.c.
"""
from copy import deepcopy
import fcntl
import os
import re
import stat
import struct
import uuid

from .manifest import Conflict, fingerprint
from .vm_template import fields, require

TUNSETIFF = 0x400454ca
TUNGETFEATURES = 0x800454cf
TUNGETIFF = 0x800454d2
TUNSETIFINDEX = 0x400454da
TUNGETDEVNETNS = 0x54e3
IFF_TAP, IFF_NO_PI, IFF_VNET_HDR, IFF_TUN_EXCL = 0x2, 0x1000, 0x4000, 0x8000
IFREQ = struct.Struct('=16sH22x')


def request(value):
    fields(value, ('nonce','name','ifindex','vnet_header'), 'exclusive ephemeral TAP request')
    require(isinstance(value['nonce'], str) and re.fullmatch('[0-9a-f]{32}', value['nonce'])
        and isinstance(value['name'], str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', value['name'])
        and not value['name'].startswith(('vnet','vif','macvtap','macvlan'))
        and type(value['ifindex']) is int and 0 < value['ifindex'] < 2**31
        and type(value['vnet_header']) is bool, 'explicit exclusive TAP identity required')
    return deepcopy(value)


def context(value):
    fields(value, ('boot_id','device','inode'), 'TAP network namespace')
    require(str(uuid.UUID(value['boot_id'])) == value['boot_id']
        and all(type(value[key]) is int and value[key] > 0 for key in ('device','inode')),
        'original TAP namespace identity required')
    return deepcopy(value)


class EphemeralTap:
    def __init__(self, spec, namespace, *, read_context, inventory, record, ioctl=fcntl.ioctl):
        self.spec, self.context = request(spec), context(namespace)
        require(struct.calcsize('P') == 8 and all(callable(fn) for fn in (read_context,inventory,record,ioctl)),
                'qualified 64-bit Linux TAP providers required')
        self.read_context, self.inventory, self.record, self.ioctl = read_context, inventory, record, ioctl
        self._fd, self._entered, self._requested, self._identity = None, False, False, None
        self._lease_token, self._birth_proof = uuid.uuid4().hex, None

    def _scope(self):
        if self.read_context() != self.context:raise Conflict('original TAP namespace changed')
        # /proc/self may describe the thread-group leader. A TUN open uses
        # the calling thread's namespace, which must match before creation.
        current = os.stat('/proc/thread-self/ns/net')
        if (current.st_dev,current.st_ino) != (self.context['device'],self.context['inode']):
            raise Conflict('current TAP thread belongs to another namespace')

    def _device(self):
        require(self._fd is not None, 'original TAP device FD closed')
        info = os.fstat(self._fd)
        require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev),os.minor(info.st_rdev)) == (10,200),
                'original Linux TUN character device required')
        value = dict(device=info.st_dev,inode=info.st_ino,mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,rdev=info.st_rdev)
        if self._identity is not None and value != self._identity:raise Conflict('original TUN FD changed')
        return value

    def __enter__(self):
        require(not self._entered, 'ephemeral TAP attempt cannot be reopened')
        self._entered = True;self._scope()
        self._fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self._identity = self._device();self._scope()
            self._record('opened', dict(device=self._identity))
            return self
        except BaseException:
            self.close();raise

    def _record(self, phase, proof):
        self.record(dict(phase=phase,request=deepcopy(self.spec),request_sha256=fingerprint(self.spec),
            context=deepcopy(self.context),proof=deepcopy(proof)))

    def _links(self):
        self._scope();links = self.inventory();self._scope()
        require(type(links) is list and all(type(link) is dict and type(link.get('ifindex')) is int
            and isinstance(link.get('ifname'),str) for link in links), 'complete typed TAP link inventory required')
        return [link for link in links if link['ifname'] == self.spec['name'] or link['ifindex'] == self.spec['ifindex']]

    def _iff(self):
        self._scope();self._device()
        raw = self.ioctl(self._fd,TUNGETIFF,bytes(IFREQ.size))
        require(isinstance(raw,bytes) and len(raw) == IFREQ.size, 'complete original TAP ioctl reply required')
        name, flags = IFREQ.unpack(raw)
        require(name.split(b'\0')[0] == self.spec['name'].encode('ascii') and flags in self._accepted_flags(),
                'original ephemeral TAP FD identity/flags differ')
        ns = self.ioctl(self._fd,TUNGETDEVNETNS)
        require(type(ns) is int and ns >= 0 and ns != self._fd, 'original TAP namespace FD required')
        try:
            info = os.fstat(ns)
            require((info.st_dev,info.st_ino) == (self.context['device'],self.context['inode']),
                    'TAP device belongs to another namespace')
        finally:os.close(ns)
        self._scope()
        return flags

    def _accepted_flags(self):
        return {IFF_TAP | IFF_NO_PI | (IFF_VNET_HDR if self.spec['vnet_header'] else 0)}

    def capture(self):
        flags = self._iff();matches = self._links()
        require(len(matches) == 1, 'original TAP link is missing or ambiguous')
        link = matches[0]
        require(link['ifname'] == self.spec['name'] and link['ifindex'] == self.spec['ifindex']
            and link.get('linkinfo',{}).get('info_kind') == 'tun'
            and link.get('ifalias','') in ('',None) and link.get('master') in (None,0)
            and type(link.get('mtu')) is int and 68 <= link['mtu'] <= 65535
            and isinstance(link.get('address'),str) and re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',link['address'])
            and type(link.get('flags')) is list and 'UP' not in link['flags'],
            'unconfigured original ephemeral TAP link required')
        if self._iff() != flags:raise Conflict('TAP flags changed during observation')
        return dict(context=deepcopy(self.context),request_sha256=fingerprint(self.spec),
            device=deepcopy(self._identity),flags=flags,link=deepcopy(link))

    def create(self):
        require(self._fd is not None and not self._requested, 'TAP creation cannot be repeated')
        self._requested = True
        self._scope();self._device()
        if self._links():raise Conflict('TAP name or requested ifindex already occupied')
        supported = self.ioctl(self._fd,TUNGETFEATURES,bytes(4))
        require(isinstance(supported,bytes) and len(supported) == 4, 'TUN feature reply required')
        flags = IFF_TAP | IFF_NO_PI | (IFF_VNET_HDR if self.spec['vnet_header'] else 0)
        require(struct.unpack('=I',supported)[0] & flags == flags, 'requested TAP features unavailable')
        self._record('create_requested',dict(device=self._identity))
        self._scope();self._device()
        if self._links():raise Conflict('TAP identity occupied after creation checkpoint')
        self.ioctl(self._fd,TUNSETIFINDEX,struct.pack('=I',self.spec['ifindex']))
        self._scope();self._device()
        # No fallback attaches an existing device: the kernel checks EXCL.
        self.ioctl(self._fd,TUNSETIFF,IFREQ.pack(self.spec['name'].encode('ascii'),flags | IFF_TUN_EXCL))
        proof = self.capture();self._record('created',proof);self._birth_proof = deepcopy(proof)
        return proof

    def close(self):
        if self._fd is not None:
            fd,self._fd = self._fd,None
            os.close(fd)

    def __exit__(self,kind,error,traceback):
        try:self.close()
        except Exception as cleanup:
            if error is None:raise
            error.add_note('original ephemeral TAP close also failed: '+str(cleanup))
