"""Read original QEMU TUN descriptors under its existing live pidfd witness.

The creator's monitored link continuity is mandatory as well: Linux fdinfo
reports a TAP name, not a stable netdevice generation. No FD is duplicated,
opened through procfs, transferred or closed here, and no PID is discovered.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
import re
import stat

from .manifest import fingerprint
from .qemu_process import PinnedQEMUProcess
from .vm_tap_device import context as validate_context
from .vm_template import require


def tun_name(raw):
    require(type(raw) is bytes and raw.endswith(b'\n') and len(raw) <= 16384,
            'complete bounded TUN fdinfo required')
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b':')
        require(separator and key and key not in fields, 'unambiguous TUN fdinfo fields required')
        fields[key] = value.strip()
    name = fields.get(b'iff', b'')
    require(re.fullmatch(rb'[A-Za-z][A-Za-z0-9_-]{0,14}', name) is not None
            and fields.get(b'ino', b'').isdigit(), 'attached TUN name and inode required')
    return name.decode('ascii'), int(fields[b'ino'])


class QEMUTapDescriptors:
    def __init__(self, process, *, verify_links, descriptor=os.stat):
        require(isinstance(process, PinnedQEMUProcess) and callable(verify_links) and callable(descriptor),
                'original pinned QEMU and monitored link continuity required')
        self.process, self.verify_links, self.descriptor = process, verify_links, descriptor
        self.record_sha256 = fingerprint(process.record)

    def _snapshot(self, names):
        process = self.process
        with ExitStack() as stack:
            proc = process._open(str(process.proc_root), None, stack, directory=True)
            root = process._open(str(process.record['process']['pid']), proc, stack, directory=True)
            information = process._open('fdinfo', root, stack, directory=True)
            descriptors = process._open('fd', root, stack, directory=True)
            entries = os.listdir(information)
            require(len(entries) <= 16384 and all(re.fullmatch('[0-9]+', name) for name in entries),
                    'complete bounded QEMU descriptor inventory required')
            result = []
            for entry in sorted(entries, key=int):
                # fd is a procfs magic link below the original PID directory.
                # stat observes it; open/read of the referenced device is forbidden.
                info = self.descriptor(entry, dir_fd=descriptors, follow_symlinks=True)
                if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(10, 200):
                    continue
                raw = process._read(entry, information, 16384)
                name, inode = tun_name(raw)
                require(name in names and inode == info.st_ino, 'foreign or replaced original QEMU TUN descriptor')
                after = self.descriptor(entry, dir_fd=descriptors, follow_symlinks=True)
                keys = ('st_dev', 'st_ino', 'st_mode', 'st_rdev')
                require(all(getattr(info, key) == getattr(after, key) for key in keys),
                        'QEMU TUN descriptor changed during read')
                result.append(dict(name=name, fd=int(entry), device=info.st_dev, inode=inode,
                                   mode=info.st_mode, rdev=info.st_rdev,
                                   fdinfo_sha256=hashlib.sha256(raw).hexdigest()))
            require(sorted(item['name'] for item in result) == names,
                    'one original QEMU descriptor per planned single-queue TAP required')
            return result

    def observe(self, names, context):
        require(type(names) is list and names and len(names) == len(set(names))
                and all(type(name) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', name) for name in names),
                'complete distinct original TAP names required')
        names = sorted(names)
        scope = validate_context(context)
        record = self.process.record
        require(fingerprint(record) == self.record_sha256
                and scope == dict(boot_id=record['process']['boot_id'], **record['namespaces']['net']),
                'original QEMU TAP namespace or process changed')
        expected = dict(names=names, context_sha256=fingerprint(scope), continuity_verified=True)
        def check():
            require(fingerprint(self.process.record) == self.record_sha256
                    and self.verify_links(deepcopy(names), deepcopy(scope)) == expected,
                    'original TAP continuity not qualified around QEMU descriptors')
        check()
        with self.process.capture(record['birth']):
            check()
            first = self._snapshot(names)
            check()
            second = self._snapshot(names)
            require(first == second, 'original QEMU TAP descriptors changed between observations')
            check()
        check()
        return dict(process_record_sha256=self.record_sha256, context_sha256=fingerprint(scope),
                    descriptors=first, continuity_verified=True)
