"""One-shot TAP handoff diagnostic in a new, otherwise empty network namespace.

No VM, libvirt connection, bridge, address or host-interface mutation. This
demonstrates single-queue kernel behaviour, not production ownership recovery.
The namespace is never exported; after any uncertain result its destruction on
process exit is the cleanup boundary. There is no reopen/retry by interface name.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import uuid

TUNSETIFF, TUNGETIFF, TUNSETPERSIST = 0x400454ca, 0x800454d2, 0x400454cb
FLAGS, EXCL, PERSIST = 0x1002, 0x8000, 0x0800
IFREQ = struct.Struct('=16sH22x')


class ProbeError(RuntimeError):
    pass


def namespace():
    info = os.stat('/proc/thread-self/ns/net')
    return [info.st_dev, info.st_ino]


class KernelTap:
    def __init__(self, name):
        self.name, self.scope = name, namespace()
        self.fds = set()

    def check_scope(self):
        if namespace() != self.scope:
            raise ProbeError('original isolated namespace changed')

    def open(self):
        self.check_scope()
        fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.fds.add(fd)
        info = os.fstat(fd)
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(10, 200):
            raise ProbeError('Linux TUN device differs')
        return fd

    def attach(self, fd, exclusive=False):
        self.check_scope()
        return fcntl.ioctl(fd, TUNSETIFF,
                           IFREQ.pack(self.name.encode('ascii'), FLAGS | (EXCL if exclusive else 0)))

    def capture(self, fd):
        self.check_scope()
        raw = fcntl.ioctl(fd, TUNGETIFF, bytes(IFREQ.size))
        name, flags = IFREQ.unpack(raw)
        if name.split(b'\0')[0] != self.name.encode('ascii') or flags & ~PERSIST != FLAGS:
            raise ProbeError('original TAP flags/name differ')
        result = dict(name=self.name, ifindex=socket.if_nametoindex(self.name),
                      namespace=self.scope[:], flags=flags & ~PERSIST)
        self.check_scope()
        return result

    def persist(self, fd, enabled):
        self.check_scope()
        self.capture(fd)
        fcntl.ioctl(fd, TUNSETPERSIST, int(enabled))

    def close(self, fd):
        self.fds.remove(fd)
        os.close(fd)

    def absent(self):
        self.check_scope()
        return all(name != self.name for _, name in socket.if_nameindex())

    def finish(self):
        for fd in tuple(self.fds):
            self.close(fd)


def handoff(tap, save):
    """Run once; no recovery/adoption and no production capability is returned."""
    if not tap.absent():
        raise ProbeError('diagnostic name already occupied')
    creator = tap.open()
    save('create_requested')
    tap.attach(creator, exclusive=True)
    birth = tap.capture(creator)
    save('created', birth=birth)
    save('persist_requested')
    tap.persist(creator, True)
    if tap.capture(creator) != birth:
        raise ProbeError('TAP differs after persistence')
    contender = tap.open()
    save('busy_check_requested')
    try:
        tap.attach(contender)
    except OSError as error:
        if error.errno != errno.EBUSY:
            raise
        save('busy_observed', errno=error.errno)
    else:
        raise ProbeError('second single-queue attachment unexpectedly succeeded')
    if tap.capture(creator) != birth:
        raise ProbeError('TAP differs before creator release')
    save('release_requested', birth=birth)
    tap.close(creator)
    save('creator_released')
    # This FD was opened before releasing the creator. No new device may be
    # created: the isolated namespace contains only this persisted original TAP.
    save('acquire_requested')
    tap.attach(contender)
    if tap.capture(contender) != birth:
        raise ProbeError('TAP identity changed during handoff')
    save('acquired', birth=birth)
    save('unpersist_requested')
    tap.persist(contender, False)
    if tap.capture(contender) != birth:
        raise ProbeError('TAP differs before final close')
    tap.close(contender)
    if not tap.absent():
        raise ProbeError('original diagnostic TAP still present')
    save('completed', cleanup_verified=True, production_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if not args.execute:
        parser.error('native diagnostic requires --execute')
    output = Path(args.output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    token = uuid.uuid4().hex
    value = dict(token=token, pid=os.getpid(), host_namespace=namespace(), events=[])

    def save(phase, **proof):
        value['events'].append(dict(phase=phase, **proof))
        path = output / ('%02d-%s.json' % (len(value['events']), phase))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    tap = None
    try:
        save('namespace_requested')
        os.unshare(os.CLONE_NEWNET)
        current = namespace()
        if current == value['host_namespace'] or socket.if_nameindex() != [(1, 'lo')]:
            raise ProbeError('fresh isolated namespace required')
        save('isolated', namespace=current)
        tap = KernelTap('dhp' + token[:11])
        handoff(tap, save)
        print(json.dumps(dict(status='completed', output=str(output), production_qualified=False)))
    except BaseException as error:
        save('failed', error=dict(type=type(error).__name__, message=str(error)),
             namespace_destruction_required=True)
        raise
    finally:
        if tap is not None:
            tap.finish()


if __name__ == '__main__':
    main()
