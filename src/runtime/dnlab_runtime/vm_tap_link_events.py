"""Original RTNL subscription for TAP continuity across descriptor handoff.

No link mutation, descriptor transfer or adoption. Register before creation,
bind a birth from its original NEWLINK event, and drain before each handoff
boundary. Overflow, malformed input, lost provenance or failed durable recording
poisons this instance. Reopening a socket cannot reconstruct its continuity.
"""
from copy import deepcopy
import errno
import os
import socket
import stat
import struct
import uuid

from .manifest import Conflict, fingerprint
from .vm_tap_device import context as validate_context
from .vm_template import require

HEADER = struct.Struct('=IHHII')
LINK = struct.Struct('=BBHiII')
ATTRIBUTE = struct.Struct('=HH')
NEWLINK, DELLINK = 16, 17


def decode(data, sender, flags):
    """Decode one complete multicast datagram from the kernel, never a dump."""
    require(type(data) is bytes and data and type(sender) is tuple and len(sender) == 2
            and sender[0] == 0 and sender[1] == 1
            and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
            'complete kernel link multicast datagram required')
    offset, events = 0, []
    while offset < len(data):
        require(len(data) - offset >= HEADER.size, 'truncated netlink header')
        length, kind, mode, sequence, port = HEADER.unpack_from(data, offset)
        require(HEADER.size <= length <= len(data) - offset and port == 0
                and not mode & 0x10, 'netlink loss, sender or interrupted message differs')
        require(kind in (NEWLINK, DELLINK), 'unexpected netlink message or event loss')
        body = data[offset + HEADER.size:offset + length]
        require(len(body) >= LINK.size, 'truncated link event')
        family, pad, hardware, index, link_flags, change = LINK.unpack_from(body)
        require(index > 0, 'positive original link ifindex required')
        cursor, name = LINK.size, None
        while cursor < len(body):
            require(len(body) - cursor >= ATTRIBUTE.size, 'truncated link attribute')
            size, attribute = ATTRIBUTE.unpack_from(body, cursor)
            require(ATTRIBUTE.size <= size <= len(body) - cursor, 'invalid link attribute length')
            if attribute & 0x3fff == 3:  # IFLA_IFNAME
                raw = body[cursor + ATTRIBUTE.size:cursor + size]
                require(name is None and 2 <= len(raw) <= 16 and raw[-1:] == b'\0'
                        and b'\0' not in raw[:-1], 'single complete link name required')
                try:
                    name = raw[:-1].decode('ascii')
                except UnicodeDecodeError as error:
                    raise Conflict('non-ASCII link name') from error
            cursor += (size + 3) & ~3
        require(name is not None and cursor == len(body), 'complete aligned link name required')
        events.append(dict(kind=kind, ifindex=index, name=name,
                           flags=link_flags, change=change, kernel_sequence=sequence))
        offset += (length + 3) & ~3
    require(offset == len(data), 'complete aligned netlink datagram required')
    return events


class TapLinkEvents:
    def __init__(self, context, *, runtime, read_context, record, socket_factory=socket.socket,
                 descriptor=os.fstat):
        require(callable(getattr(runtime, 'check', None)) and callable(read_context)
                and callable(record) and callable(socket_factory) and callable(descriptor),
                'original runtime, namespace and durable event recorder required')
        self.context = validate_context(context)
        self.runtime, self.read_context, self.record = runtime, read_context, record
        self.socket_factory, self.descriptor = socket_factory, descriptor
        self.id, self.epoch = uuid.uuid4().hex, fingerprint(runtime.check())
        self.pid, self.socket, self.identity = os.getpid(), None, None
        self.poisoned, self.opened, self.events, self.births = False, False, [], {}

    def _scope(self):
        current = os.stat('/proc/thread-self/ns/net')
        require(not self.poisoned and os.getpid() == self.pid
                and fingerprint(self.runtime.check()) == self.epoch
                and self.read_context() == self.context
                and (current.st_dev, current.st_ino) == (self.context['device'], self.context['inode']),
                'original TAP event monitor lost')

    def _identity(self):
        info = self.descriptor(self.socket.fileno())
        require(stat.S_ISSOCK(info.st_mode), 'original netlink socket required')
        return dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode)

    def _check(self):
        self._scope()
        require(self.socket is not None and self._identity() == self.identity
                and self.socket.getsockopt(270, 5) == 0,  # NETLINK_NO_ENOBUFS must stay disabled
                'original TAP event socket replaced or loss reporting disabled')

    def open(self):
        require(not self.opened, 'TAP event subscription cannot be reopened')
        self.opened = True
        try:
            self._scope()
            self.record(dict(phase='subscribe_requested', monitor_id=self.id,
                             epoch=self.epoch, context=deepcopy(self.context)))
            self.socket = self.socket_factory(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
            self.socket.setblocking(False)
            self.socket.bind((0, 1))  # RTMGRP_LINK, before the creator allocates any TAP
            self.identity = self._identity()
            self._check()
            self.record(dict(phase='subscribed', monitor_id=self.id, epoch=self.epoch,
                             context=deepcopy(self.context), socket=deepcopy(self.identity)))
            return self
        except BaseException:
            self.poisoned = True
            if self.socket is not None:
                self.socket.close()
                self.socket = None
            raise

    def drain(self):
        try:
            self._check()
            for _ in range(256):
                try:
                    data, ancillary, flags, sender = self.socket.recvmsg(65536)
                except BlockingIOError as error:
                    require(error.errno in (errno.EAGAIN, errno.EWOULDBLOCK), 'unknown netlink receive refusal')
                    self._check()
                    return deepcopy(self.events)
                require(not ancillary, 'unexpected netlink control data')
                batch = decode(data, sender, flags)
                self._check()
                # Save raw input and parsed events before exposing them. A failed
                # save consumes this socket's input and permanently loses proof.
                self.record(dict(phase='events', monitor_id=self.id, first=len(self.events) + 1,
                                 raw=data.hex(), sender=list(sender), flags=flags, events=deepcopy(batch)))
                self.events.extend(batch)
            raise Conflict('bounded TAP event queue not drained')
        except BaseException:
            self.poisoned = True
            raise

    def birth(self, name, ifindex):
        require(type(name) is str and type(ifindex) is int and ifindex > 0,
                'original TAP name and ifindex required')
        self.drain()
        relevant = [(n + 1, e) for n, e in enumerate(self.events)
                    if e['name'] == name or e['ifindex'] == ifindex]
        require(relevant and all(e['kind'] == NEWLINK and e['name'] == name
                                and e['ifindex'] == ifindex for _, e in relevant),
                'uninterrupted original TAP NEWLINK birth required')
        value = dict(monitor_id=self.id, epoch=self.epoch, context=deepcopy(self.context),
                     name=name, ifindex=ifindex, sequence=relevant[0][0])
        key = (name, ifindex)
        if key in self.births:
            require(self.births[key] == value, 'original TAP event birth cannot be replaced')
        else:
            try:
                self.record(dict(phase='birth_bound', birth=deepcopy(value)))
            except BaseException:
                self.poisoned = True
                raise
            self.births[key] = deepcopy(value)
        return deepcopy(value)

    def verify(self, birth):
        self.drain()
        key = (birth.get('name'), birth.get('ifindex'))
        require(key in self.births and self.births[key] == birth, 'original TAP monitor birth missing')
        relevant = self.events[birth['sequence'] - 1:]
        require(all(e['kind'] == NEWLINK and e['name'] == birth['name'] and e['ifindex'] == birth['ifindex']
                    for e in relevant if e['name'] == birth['name'] or e['ifindex'] == birth['ifindex']),
                'original TAP removed, renamed or replaced')
        self._check()
        return dict(birth_sha256=fingerprint(birth), cursor=len(self.events), continuity_verified=True)

    def close(self):
        self.poisoned = True
        if self.socket is not None:
            self.socket.close()
            self.socket = None
