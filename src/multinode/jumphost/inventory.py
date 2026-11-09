#!/usr/bin/env python3
"""Persist relay inventory independently of immutable container environment."""
import grp
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


def publish(request, directory=Path('/etc'), group=None):
    group = grp.getgrnam('labuser').gr_gid if group is None else group
    bundle = directory / 'dnlab-inventory.json'
    targets = {'dnlab-vds': 0o644, 'dnlab-relays': 0o640, 'motd': 0o644,
               'dnlab-inventory.json': 0o600}
    for name, mode in targets.items():
        path = directory / name
        try: info = path.lstat()
        except FileNotFoundError: continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022):
            raise RuntimeError('inventory file ownership differs')
        if name == 'dnlab-inventory.json' and stat.S_IMODE(info.st_mode) != mode:
            raise RuntimeError('inventory bundle permissions differ')
    current = json.loads(bundle.read_text()) if bundle.exists() else None
    if request['action'] == 'inspect':
        if current is not None:
            for name, field in (('dnlab-vds','vds'), ('dnlab-relays','relays'), ('motd','motd')):
                path = directory / name
                if not path.exists() or path.read_text() != current[field]:
                    raise RuntimeError('derived inventory differs; recovery required')
                if stat.S_IMODE(path.stat().st_mode) != targets[name]:
                    raise RuntimeError('derived inventory permissions differ')
        return current
    desired = current if request['action'] == 'restore' else request['desired']
    if desired is None: raise RuntimeError('persistent inventory missing')
    if request['action'] == 'apply' and current not in (request['previous'], desired):
        raise RuntimeError('persistent inventory replaced')
    if set(desired) != {'lab', 'generation', 'container_id', 'request_id', 'vds', 'relays', 'motd'}:
        raise RuntimeError('invalid persistent inventory')
    files = {'dnlab-vds': desired['vds'], 'dnlab-relays': desired['relays'], 'motd': desired['motd']}
    # Persist the authoritative source first. Recovery and subsequent entrypoint
    # invocations finish all derived files after an interrupted publication.
    files = {'dnlab-inventory.json': json.dumps(desired, sort_keys=True), **files}
    for name, content in files.items():
        fd, temporary = tempfile.mkstemp(prefix='.dnlab-inventory-', dir=directory)
        try:
            with os.fdopen(fd, 'w') as stream:
                os.fchown(stream.fileno(), 0, group if name in ('dnlab-vds', 'dnlab-relays') else 0)
                os.fchmod(stream.fileno(), targets[name])
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, directory / name)
            parent = os.open(directory, os.O_DIRECTORY)
            try: os.fsync(parent)
            finally: os.close(parent)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    return desired


if __name__ == '__main__':
    request = {'action': 'restore'} if sys.argv[1:] == ['--restore'] else json.load(sys.stdin)
    print(json.dumps(publish(request)))
