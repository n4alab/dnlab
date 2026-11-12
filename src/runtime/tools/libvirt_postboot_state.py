"""Explicit admission of an empty postboot session and bounded capability cache.

No resource is removed or attributed to an old daemon. The approved observation
must be persisted with the successor intent before commands are released. Any
VM definition, saved state, unexpected path or changed approved tree is refused.
"""
from copy import deepcopy
import hashlib
import os
import re
import stat
from xml.etree import ElementTree as ET

from dnlab_runtime.libvirt_activation import SessionActivation
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_bundle import metadata
from tools.libvirt_initial_state import InitialSessionState
from tools.libvirt_service_generation import directory_identity
from tools.vm_host_inventory import entry


def empty_tree_layout(profile):
    mutable = profile['driver_layout']['mutable_root']
    cache = profile['client_environment']['XDG_CACHE_HOME']
    data = profile['client_environment']['XDG_DATA_HOME']
    return {
        mutable: {'': {'checkpoint', 'dump', 'lib', 'nvram', 'ram', 'save', 'snapshot'},
                  **{name:set() for name in ('checkpoint','dump','lib','nvram','ram','save','snapshot')}},
        cache: {'': {'libvirt'}, 'libvirt': {'qemu'}, 'libvirt/qemu': {'cache'},
                'libvirt/qemu/cache': {'capabilities'}, 'libvirt/qemu/cache/capabilities': None},
        data: {'': set()},
    }


class PostBootEmptyState(InitialSessionState):
    def __init__(self, root, installation, predecessor, *, approved=None):
        SessionActivation._successor_source(predecessor, installation)
        super().__init__(root, installation)
        self.binding = dict(kind='postboot-empty-state-v1', installation_sha256=fingerprint(installation),
                            predecessor_sha256=fingerprint(predecessor))
        self.approved = deepcopy(approved)
        self.trees = empty_tree_layout(installation['profile'])
        if approved is not None and (set(approved) != {'binding', 'trees'} or approved['binding'] != self.binding):
            raise Conflict('original postboot empty-state admission differs')

    def _tree(self, path, layout):
        result = {}
        uid, gid = self.session['uid'], self.session['gid']
        root_identity = self.identities[path]

        def read_directory(fd, relative):
            before = os.fstat(fd)
            if ((before.st_uid, before.st_gid) != (uid, gid) or before.st_mode != stat.S_IFDIR | 0o700
                    or before.st_dev != root_identity['device']):
                raise Conflict('private postboot directory required: ' + path + '/' + relative)
            result[relative] = dict(metadata=list(metadata(before)))
            names = sorted(os.listdir(fd))
            if len(names) > 128:raise Conflict('postboot directory inventory exceeds bound')
            allowed = layout[relative]
            for name in names:
                child = name if not relative else relative + '/' + name
                if allowed is None:
                    if not re.fullmatch('[0-9a-f]{64}\\.xml', name):
                        raise Conflict('unexpected postboot capability cache entry')
                    pin = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        info = os.fstat(pin)
                        if (info.st_mode != stat.S_IFREG | 0o600 or info.st_nlink != 1
                                or (info.st_uid, info.st_gid) != (uid, gid) or info.st_dev != before.st_dev
                                or not 0 < info.st_size <= 1024*1024):
                            raise Conflict('bounded private regular capability cache required')
                        data_fd = os.open('/proc/self/fd/'+str(pin), os.O_RDONLY | os.O_CLOEXEC)
                        try:
                            if metadata(os.fstat(data_fd)) != metadata(info):raise Conflict('cache identity changed')
                            raw = bytearray()
                            while len(raw) <= 1024*1024:
                                chunk = os.read(data_fd, min(65536, 1024*1024+1-len(raw)))
                                if not chunk:break
                                raw.extend(chunk)
                            if (len(raw) != info.st_size or metadata(os.fstat(data_fd)) != metadata(info)
                                    or metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) != metadata(info)):
                                raise Conflict('capability cache changed during observation')
                        finally:os.close(data_fd)
                    finally:os.close(pin)
                    if b'\0' in raw or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                        raise Conflict('capability cache declarations refused')
                    try:tree = ET.fromstring(raw)
                    except ET.ParseError as error:raise Conflict('invalid capability cache XML') from error
                    if tree.tag != 'qemuCaps':raise Conflict('capability cache root differs')
                    result[child] = dict(metadata=list(metadata(info)), sha256=hashlib.sha256(raw).hexdigest())
                else:
                    if name not in allowed:raise Conflict('unexpected postboot domain or state entry: ' + path + '/' + child)
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        read_directory(child_fd, child)
                        if metadata(os.fstat(child_fd)) != metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                            raise Conflict('postboot directory path changed')
                    finally:os.close(child_fd)
            if metadata(os.fstat(fd)) != metadata(before):raise Conflict('postboot directory changed during observation')

        with entry(self.root, path.lstrip('/')) as (parent, name, info):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                if directory_identity(os.fstat(fd)) != root_identity:raise Conflict('original postboot tree root differs')
                read_directory(fd, '')
                if metadata(os.fstat(fd)) != metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                    raise Conflict('postboot tree root path changed')
            finally:os.close(fd)
        return result

    def capture(self):
        def read():return {path:self._tree(path, layout) for path,layout in self.trees.items()}
        trees = read()
        if read() != trees:raise Conflict('postboot empty trees changed between observations')
        return dict(binding=deepcopy(self.binding), trees=trees)

    def __call__(self, receipts):
        if receipts['dnlab-libvirtd.service'] is not None:return
        if self.approved is None or self.capture() != self.approved:
            raise Conflict('original approved postboot empty-state observation required')
        # Retain first-start checks on config/data/runtime. Only the explicitly
        # approved persistent trees replace the pristine-content requirement.
        helpers = {}
        for role in ('virtlogd', 'virtlockd'):
            if receipts['dnlab-'+role+'.service'] is not None:
                helpers.update({role+'.pid':stat.S_IFREG, role+'-sock':stat.S_IFSOCK,
                                role+'-admin-sock':stat.S_IFSOCK})
        def read():
            return {path:self._inspect(path, required, helpers if path == self.runtime else {})
                    for path,required in self.contents.items() if path not in self.trees}
        if read() != read():raise Conflict('postboot initial state changed during preflight')
