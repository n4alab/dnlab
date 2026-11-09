"""Readonly identities of OS directories above planned installation targets.

These are dependencies, never resources adopted or changed by the installer.
Child activity is permitted; replacement and permission changes are not.
"""
from contextlib import ExitStack
import os
from pathlib import PurePosixPath
import stat

from dnlab_runtime.manifest import Conflict


def parent_paths(profile):
    planned = {item['path'] for item in profile['directories']}
    paths = set()
    for target in planned | set(profile['files']):
        paths.update(str(parent) for parent in PurePosixPath(target).parents)
    return sorted(paths - planned)


def identity(info):
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o755):
        raise Conflict('installation OS parent must be a root-owned 0755 directory')
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def collect(root, profile):
    result = {}
    try:
        with ExitStack() as stack:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            for path in parent_paths(profile):
                with ExitStack() as parents:
                    current = fd
                    for part in PurePosixPath(path).parts[1:]:
                        current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                          dir_fd=current)
                        parents.callback(os.close, current)
                    result[path] = identity(os.fstat(current))
    except OSError as error:
        raise Conflict('installation OS parent unavailable or replaced') from error
    return result
