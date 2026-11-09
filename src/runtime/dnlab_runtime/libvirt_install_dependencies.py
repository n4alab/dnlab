"""Read-only dependencies explicitly selected from the installation profile.

Matching a directory does not claim its birth or authorize modifying it. The
caller must persist this receipt in the original installation intent and compare
it on every observation. No path discovery or ownership repair is performed.
"""
from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import PurePosixPath
import stat

from .manifest import Conflict


class InstallationDirectoryDependencies:
    def __init__(self, root, specs):
        self.root = os.fspath(root)
        self.specs = {}
        if not os.path.isabs(self.root):raise Conflict('absolute dependency root required')
        for spec in specs:
            if (not isinstance(spec, dict) or set(spec) != {'key', 'kind', 'path', 'uid', 'gid', 'mode'}
                    or spec['kind'] != 'directory' or not isinstance(spec['path'], str)
                    or not spec['path'].startswith('/') or str(PurePosixPath(spec['path'])) != spec['path']
                    or '..' in PurePosixPath(spec['path']).parts or spec['path'] == '/'
                    or spec['key'] != 'directory:' + spec['path']
                    or any(type(spec[k]) is not int for k in ('uid', 'gid', 'mode'))
                    or (spec['uid'], spec['gid'], spec['mode']) != (0, 0, 0o755)
                    or spec['key'] in self.specs):
                raise Conflict('explicit root-controlled directory dependency spec required')
            self.specs[spec['key']] = deepcopy(spec)
        if not self.specs:raise Conflict('explicit directory dependencies required')

    @staticmethod
    def _identity(fd):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode)
                or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o755)):
            raise Conflict('directory dependency ownership or permissions differ')
        return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                    gid=info.st_gid, mode=stat.S_IMODE(info.st_mode), kind='directory')

    def _snapshot(self, spec):
        result = {}
        try:
            with ExitStack() as stack:
                fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                stack.callback(os.close, fd)
                result['/'] = self._identity(fd)
                path = PurePosixPath('/')
                for part in PurePosixPath(spec['path']).parts[1:]:
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    stack.callback(os.close, fd)
                    path /= part
                    result[str(path)] = self._identity(fd)
        except OSError as error:
            raise Conflict('original directory dependency missing or unresolved') from error
        return dict(dependency='existing_directory', path=spec['path'],
                    identity=result.pop(spec['path']), ancestors=result)

    def __call__(self, spec):
        if not isinstance(spec, dict) or self.specs.get(spec.get('key')) != spec:
            raise Conflict('directory dependency was not explicitly selected')
        first = self._snapshot(spec)
        if self._snapshot(spec) != first:
            raise Conflict('directory dependency changed during observation')
        return first
