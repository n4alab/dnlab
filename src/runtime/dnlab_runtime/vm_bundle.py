"""Read and authenticate a filesystem template without executing its assets.

Directory/file descriptors pin each path while hashing. Symlinks, replaced
paths, duplicate JSON keys and content differing from the manifest are refused.
This is a read-time proof, not a disk lock or hypervisor qualification.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from .vm_template import digest, require, template_digest, validate_template


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate template JSON key')
        result[key] = value
    return result


@contextmanager
def pinned_file(root_fd, relative):
    with ExitStack() as stack:
        parent = root_fd
        guards = []
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, fd)
            before = metadata(os.fstat(fd))
            require(before == metadata(os.stat(part, dir_fd=parent, follow_symlinks=False)), 'bundle directory path changed')
            guards.append((parent, part, fd, before))
            parent = fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), 'regular bundle asset required')
        before = metadata(info)
        require(before == metadata(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)), 'bundle asset path changed')
        yield fd, info
        require(before == metadata(os.fstat(fd)) == metadata(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
                'bundle asset changed during read')
        for parent, part, fd, before in reversed(guards):
            require(before == metadata(os.fstat(fd)) == metadata(os.stat(part, dir_fd=parent, follow_symlinks=False)),
                    'bundle directory changed during read')


def read_bundle(directory, expected_digest):
    """Verify a pinned manifest and its declared disk/firmware/config assets."""
    require(digest(expected_digest), 'immutable template digest required')
    directory = Path(directory)
    require(directory.is_absolute(), 'absolute template bundle path required')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = metadata(os.fstat(fd))
        require(before == metadata(os.stat(directory, follow_symlinks=False)), 'bundle root changed')
        with pinned_file(fd, 'manifest.json') as (manifest_fd, info):
            manifest_metadata = metadata(info)
            require(0 < info.st_size <= 1024 * 1024, 'bounded template manifest required')
            raw = bytearray()
            while True:
                chunk = os.read(manifest_fd, min(65536, 1024 * 1024 + 1 - len(raw)))
                if not chunk:break
                raw.extend(chunk)
                require(len(raw) <= 1024 * 1024, 'template manifest grew beyond bound')
            template = validate_template(json.loads(raw, object_pairs_hook=unique_pairs))
            require(template_digest(template) == expected_digest, 'template manifest digest differs')
        proofs = {}
        for name, asset in template['assets'].items():
            with pinned_file(fd, asset['path']) as (asset_fd, info):
                require(info.st_size == asset['size'], 'template asset size differs')
                hasher = hashlib.sha256(); total = 0
                while True:
                    chunk = os.read(asset_fd, min(1024 * 1024, asset['size'] + 1 - total))
                    if not chunk:break
                    total += len(chunk)
                    require(total <= asset['size'], 'template asset grew during read')
                    hasher.update(chunk)
                require(total == asset['size'] and hasher.hexdigest() == asset['sha256'], 'template asset content differs')
                proofs[name] = {'metadata': list(metadata(info)), 'sha256': hasher.hexdigest()}
        # Recheck earlier files after hashing later assets, so a mutation of
        # the manifest or an already-read disk cannot produce a stale receipt.
        observed_files = [('manifest.json', manifest_metadata)] + [
            (asset['path'], tuple(proofs[name]['metadata'])) for name, asset in template['assets'].items()]
        for path, expected in observed_files:
            with pinned_file(fd, path) as (_, info):
                require(metadata(info) == expected, 'bundle member changed before final verification')
        # All descriptors have been closed before return, including on errors.
        require(before == metadata(os.fstat(fd)) == metadata(os.stat(directory, follow_symlinks=False)), 'bundle root changed during read')
        return {'template': template, 'template_sha256': expected_digest,
                'directory_metadata': list(before), 'assets': proofs}
    finally:
        os.close(fd)
