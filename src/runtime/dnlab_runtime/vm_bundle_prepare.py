"""One-shot offline preparation of a content-addressed VM bundle.

The caller owns a private parent FD and pinned source FDs. Existing targets,
including incomplete attempts, are refused. Failure preserves artifacts and
never authorizes reuse or cleanup. Publishing manifest.json is the last step;
no VM, overlay, conversion, launcher, or hypervisor operation is performed.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import PurePosixPath
import stat

from .libvirt_configuration_swap import NOREPLACE, rename_siblings
from .manifest import canonical
from .vm_bundle import metadata
from .vm_template import require, template_digest, validate_template


def _write(fd, content):
    remaining = memoryview(content)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError('bundle write made no progress')
        remaining = remaining[written:]


def prepare_bundle(parent, template, sources):
    """Return the directory name only after durable publication and hash checks.

    Source descriptors remain owned by the caller and offsets are preserved.
    The returned name is the canonical template digest; consumers must still
    use read_bundle and qualify image format/backing chains and host access.
    """
    template = validate_template(template)
    assets = template['assets']
    require(type(sources) is dict and set(sources) == set(assets), 'exact bundle source FD inventory required')
    parent_info = os.fstat(parent)
    require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.geteuid()
            and not parent_info.st_mode & 0o077, 'private owned bundle parent directory FD required')
    paths = {PurePosixPath(asset['path']) for asset in assets.values()}
    reserved = {'manifest.json', '.manifest.pending', 'preparation.json'}
    require(all(path.parts[0] not in reserved and not any(other in path.parents for other in paths)
                for path in paths), 'bundle assets conflict with metadata or parent paths')
    original = {}
    for key, asset in assets.items():
        require(type(sources[key]) is int and sources[key] >= 0, 'original source descriptor required')
        info = os.fstat(sources[key])
        require(stat.S_ISREG(info.st_mode) and info.st_size == asset['size'], 'original regular bundle source size differs')
        original[key] = metadata(info)
    name = template_digest(template)
    # mkdir is exclusive: a previous uncertain or foreign attempt is not adopted.
    os.mkdir(name, mode=0o700, dir_fd=parent)
    os.fsync(parent)
    with ExitStack() as stack:
        root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, root)
        directories = {PurePosixPath('.'): root}

        def file(directory, filename):
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            stack.callback(os.close, fd)
            return fd

        def seal(fd):
            os.fchmod(fd, 0o444)
            os.fsync(fd)

        intent = file(root, 'preparation.json')
        _write(intent, canonical(dict(template_sha256=name, source_metadata=original)).encode() + b'\n')
        seal(intent)
        os.fsync(root)
        for key, asset in assets.items():
            relative = PurePosixPath(asset['path'])
            current = PurePosixPath('.')
            for part in relative.parts[:-1]:
                target = current / part
                if target not in directories:
                    os.mkdir(part, mode=0o700, dir_fd=directories[current])
                    os.fsync(directories[current])
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=directories[current])
                    stack.callback(os.close, fd)
                    directories[target] = fd
                current = target
            target = file(directories[current], relative.name)
            hashed = hashlib.sha256()
            offset = 0
            while offset < asset['size']:
                chunk = os.pread(sources[key], min(1024 * 1024, asset['size'] - offset), offset)
                require(bool(chunk), 'bundle source truncated during copy')
                hashed.update(chunk)
                _write(target, chunk)
                offset += len(chunk)
            require(not os.pread(sources[key], 1, offset) and hashed.hexdigest() == asset['sha256']
                    and metadata(os.fstat(sources[key])) == original[key], 'bundle source content changed or differs')
            seal(target)
            os.fsync(directories[current])
        require(all(metadata(os.fstat(sources[key])) == expected for key, expected in original.items()),
                'bundle source changed before publication')
        manifest = file(root, '.manifest.pending')
        _write(manifest, canonical(template).encode() + b'\n')
        seal(manifest)
        for fd in reversed(list(directories.values())[1:]):
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        rename_siblings(root, '.manifest.pending', 'manifest.json', NOREPLACE)
        os.fchmod(root, 0o555)
        os.fsync(root)
        os.fsync(parent)
    return name
