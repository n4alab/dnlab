"""Minimal readonly prerequisite inventory; never opens libvirt or runs tools.

Presence/hashes are diagnostics, not a KVM, permission or packaging qualification.
The CLI requires an explicit host-collection flag or a synthetic filesystem root.
Reports go only to stdout; callers must capture them in private durable output.
"""
import argparse
from contextlib import ExitStack, contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.manifest import Conflict, identifier
from dnlab_runtime.vm_bundle import metadata, pinned_file

BINARIES = ('usr/bin/qemu-system-x86_64', 'usr/bin/qemu-img', 'usr/bin/virsh',
            'usr/sbin/virtqemud', 'usr/sbin/libvirtd', 'usr/libexec/qemu-kvm')
CONFIGS = ('etc/os-release', 'usr/lib/os-release', 'etc/libvirt/qemu.conf',
           'etc/libvirt/virtqemud.conf', 'etc/libvirt/libvirtd.conf')
DEVICES = ('dev/kvm', 'dev/net/tun')
SHARED_SOCKETS = ('run/libvirt/virtqemud-sock', 'run/libvirt/libvirt-sock')


@contextmanager
def entry(root, relative):
    with ExitStack() as stack:
        parent = root
        parts = relative.split('/')
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, fd)
            parent = fd
        info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        yield parent, parts[-1], info
        if metadata(info) != metadata(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)):
            raise Conflict('inventory path changed during observation: ' + relative)


def regular(root, relative, limit):
    with pinned_file(root, relative) as (fd, info):
        if info.st_size > limit:raise Conflict('inventory file exceeds bound: ' + relative)
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:break
            data.extend(chunk)
        if len(data) > limit:raise Conflict('inventory file grew beyond bound: ' + relative)
        return bytes(data)


def probe(root, relative, *, content=False, limit=1024*1024):
    try:
        with entry(root, relative) as (parent, name, info):
            value = {'status': 'present', 'metadata': list(metadata(info))}
            if stat.S_ISLNK(info.st_mode):
                value.update(kind='symlink', target=os.readlink(name, dir_fd=parent), followed=False)
            elif stat.S_ISREG(info.st_mode):
                value['kind'] = 'regular'
                if content:
                    value['sha256'] = hashlib.sha256(regular(root, relative, limit)).hexdigest()
            elif stat.S_ISCHR(info.st_mode):
                value.update(kind='character-device', major=os.major(info.st_rdev), minor=os.minor(info.st_rdev))
            elif stat.S_ISSOCK(info.st_mode):value['kind'] = 'socket'
            elif stat.S_ISDIR(info.st_mode):value['kind'] = 'directory'
            else:value['kind'] = 'unsupported'
            return value
    except OSError as error:
        if error.errno == errno.ENOENT:return {'status': 'absent'}
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            return {'status': 'unresolved', 'reason': 'symlink or non-directory component', 'errno': error.errno}
        raise


def collect(root, *, host_id, account):
    identifier(host_id, 'inventory host')
    if not isinstance(account, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', account):
        raise Conflict('explicit local account name required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = regular(fd, 'proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', first):
            raise Conflict('canonical boot ID required')
        rows = {}
        for path in BINARIES:rows[path] = probe(fd, path, content=True, limit=128*1024*1024)
        for path in CONFIGS:rows[path] = probe(fd, path, content=True)
        for path in DEVICES + SHARED_SOCKETS:rows[path] = probe(fd, path)
        passwd = regular(fd, 'etc/passwd', 1024*1024).decode('utf-8')
        matches = [line.split(':') for line in passwd.splitlines() if line.split(':',1)[0] == account]
        local = None
        if matches:
            if len(matches) != 1 or len(matches[0]) != 7:raise Conflict('local account is ambiguous')
            item = matches[0]
            if not item[2].isdecimal() or not item[3].isdecimal():raise Conflict('local account IDs malformed')
            local = {'name': account, 'uid': int(item[2]), 'gid': int(item[3]), 'home': item[5], 'shell': item[6]}
            for path in (f'run/user/{local["uid"]}/libvirt/libvirt-sock',
                         f'run/user/{local["uid"]}/libvirt/virtqemud-sock'):
                rows[path] = probe(fd, path)
        second = regular(fd, 'proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if first != second:raise Conflict('boot changed during VM prerequisite inventory')
        return {'status': 'collected', 'qualified': False, 'host_id': host_id, 'boot_id': first,
                'account_requested': account, 'local_account': local, 'paths': rows,
                'limitations': ['No binaries or version commands executed; no libvirt connection opened',
                    'No device opened, ioctl, socket connection, account or service operation',
                    'Symlinks are reported, not followed; absent account is not created',
                    'No proof of KVM/TAP access, machine support, service ownership or readiness']}
    finally:os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--collect-host', action='store_true')
    source.add_argument('--fixture-root', type=Path)
    parser.add_argument('--host-id', required=True)
    parser.add_argument('--account', default='dnlab-libvirt')
    args = parser.parse_args(argv)
    root = Path('/') if args.collect_host else args.fixture_root
    if not args.collect_host and root.resolve() == Path('/'):
        parser.error('host root requires explicit --collect-host')
    try:
        result = collect(root, host_id=args.host_id, account=args.account)
    except Exception as error:
        print(json.dumps({'status': 'incomplete', 'qualified': False,
                          'error_type': type(error).__name__, 'error': str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
