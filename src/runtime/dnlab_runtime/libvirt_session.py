"""Dedicated non-root session contract; host observation is supplied explicitly."""
from copy import deepcopy
from pathlib import PurePosixPath
import stat

from .libvirt_xml import absolute
from .manifest import Conflict, fingerprint, identifier
from .vm_template import digest, fields, require


class DedicatedSession:
    def __init__(self, profile, observe):
        fields(profile, ('host_id', 'uid', 'gid', 'uri', 'socket', 'state_root', 'runtime_root'), 'dedicated session')
        identifier(profile['host_id'], 'session host')
        require(type(profile['uid']) is int and profile['uid'] > 0
                and type(profile['gid']) is int and profile['gid'] > 0
                and profile['uri'] == 'qemu:///session' and callable(observe), 'dedicated non-root libvirt session required')
        for key in ('socket', 'state_root', 'runtime_root'):absolute(profile[key])
        require(PurePosixPath(profile['socket']).is_relative_to(profile['runtime_root'])
                and profile['socket'] != profile['runtime_root']
                and profile['state_root'] != profile['runtime_root'], 'separate state and private runtime/socket paths required')
        self.profile, self.observe = deepcopy(profile), observe

    def proof(self):
        value = self.observe()
        fields(value, ('profile_sha256', 'daemon', 'socket', 'directories', 'config_sha256'), 'session proof')
        require(value['profile_sha256'] == fingerprint(self.profile) and digest(value['config_sha256']), 'session profile or configuration differs')
        daemon = value['daemon']
        fields(daemon, ('uid', 'gid', 'boot_id', 'pid', 'start_ticks', 'executable_sha256'), 'session daemon')
        require(daemon['uid'] == self.profile['uid'] and daemon['gid'] == self.profile['gid']
                and isinstance(daemon['boot_id'], str) and daemon['boot_id']
                and type(daemon['pid']) is int and daemon['pid'] > 0
                and type(daemon['start_ticks']) is int and daemon['start_ticks'] > 0
                and digest(daemon['executable_sha256']), 'original session daemon identity required')
        fields(value['directories'], ('state', 'runtime'), 'session directories')
        for label, info, expected_type in [('socket', value['socket'], stat.S_IFSOCK),
                ('state', value['directories']['state'], stat.S_IFDIR), ('runtime', value['directories']['runtime'], stat.S_IFDIR)]:
            fields(info, ('uid', 'gid', 'device', 'inode', 'mode'), label)
            require(all(type(v) is int and v >= 0 for v in info.values())
                    and info['uid'] == self.profile['uid'] and info['gid'] == self.profile['gid']
                    and stat.S_IFMT(info['mode']) == expected_type and not (info['mode'] & 0o077),
                    'private dedicated session resource required: ' + label)
        return deepcopy(value)

    def verify(self, expected_sha256):
        require(digest(expected_sha256), 'pinned session proof required')
        value = self.proof()
        if fingerprint(value) != expected_sha256:raise Conflict('original libvirt session generation changed')
        return value
