"""Blocked, single-PID qcow2 formatter for one already recorded empty inode."""
import os
import re
import stat
from copy import deepcopy

from .libvirt_account_worker import ENVIRONMENT, binary_proof, frame
from .libvirt_xml import absolute
from .manifest import Conflict, canonical, fingerprint
from .vm_template import digest, fields, require

MARKER = 'user.dnlab.vm.overlay'


def file_identity(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'single-link regular VM overlay required')
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def validate_command(command):
    fields(command, ('request_sha256', 'binary', 'argv', 'environment', 'target'), 'VM format command')
    binary, target = command['binary'], command['target']
    fields(binary, ('path', 'sha256'), 'VM format binary')
    fields(target, ('fd', 'identity', 'base_path', 'base_format'), 'VM format target')
    require(binary['path'] == '/usr/bin/qemu-img' and digest(binary['sha256']) and digest(command['request_sha256'])
            and command['environment'] == ENVIRONMENT and type(target['fd']) is int and 3 <= target['fd'] < 2**20,
            'pinned qemu-img and original inherited target required')
    absolute(target['base_path'])
    require(target['base_format'] in ('qcow2', 'raw'), 'explicit original base format required')
    identity = target['identity']
    fields(identity, ('device', 'inode', 'uid', 'gid', 'mode'), 'VM format inode')
    require(all(type(value) is int and value >= 0 for value in identity.values())
            and identity['inode'] > 0 and identity['mode'] == 0o600, 'original private VM format inode required')
    expected = [binary['path'], 'create', '-q', '-f', 'qcow2', '-F', target['base_format'],
                '-o', 'compat=1.1,lazy_refcounts=off', '-b', target['base_path'], f'/proc/self/fd/{target["fd"]}']
    require(command['argv'] == expected, 'fixed VM overlay create command required')
    return command


def command_plan(request, binary, target_fd, identity):
    fields(request, ('operation_id', 'nonce', 'spec'), 'VM format request')
    require(isinstance(request['operation_id'], str) and re.fullmatch('[0-9a-f]{32}', request['operation_id'])
            and isinstance(request['nonce'], str) and re.fullmatch('[0-9a-f]{32}', request['nonce']),
            'original VM format operation and nonce required')
    spec = request['spec']
    fields(spec, ('id', 'path', 'base_path', 'base_sha256', 'base_format', 'uid', 'gid', 'mode'), 'VM format specification')
    absolute(spec['path'])
    require(digest(spec['base_sha256']) and all(identity.get(key) == spec[key] for key in ('uid', 'gid', 'mode')),
            'original VM format specification/credentials required')
    target = dict(fd=target_fd, identity=deepcopy(identity), base_path=spec['base_path'], base_format=spec['base_format'])
    command = dict(request_sha256=fingerprint(request), binary=deepcopy(binary), target=target, environment=dict(ENVIRONMENT),
                   argv=[binary['path'], 'create', '-q', '-f', 'qcow2', '-F', target['base_format'],
                         '-o', 'compat=1.1,lazy_refcounts=off', '-b', target['base_path'], f'/proc/self/fd/{target_fd}'])
    return validate_command(command)


def serve(source, sink, binary_fd, target_fd, *, execute):
    packet = frame(source)
    fields(packet, ('token', 'command'), 'VM format worker packet')
    require(isinstance(packet['token'], str) and re.fullmatch('[0-9a-f]{32}', packet['token']), 'original format worker token required')
    command = validate_command(packet['command'])
    require(os.geteuid() == 0 and target_fd == command['target']['fd'] and target_fd != binary_fd,
            'original privileged formatter descriptors required')
    original = binary_proof(binary_fd, command['binary']['sha256'])

    def empty_original():
        info = os.fstat(target_fd)
        require(file_identity(info) == command['target']['identity'] and info.st_size == 0
                and os.getxattr(target_fd, MARKER) == command['request_sha256'].encode('ascii'),
                'original empty VM overlay inode/marker differs')

    empty_original()
    hashed = fingerprint(command)
    sink.write(canonical(dict(ready=packet['token'], command_sha256=hashed)) + '\n'); sink.flush()
    require(frame(source) == dict(release=packet['token'], command_sha256=hashed), 'original VM formatter release differs')
    require(binary_proof(binary_fd, command['binary']['sha256']) == original, 'original formatter executable changed')
    empty_original()
    execute(binary_fd, command['argv'], command['environment'])
    raise Conflict('VM formatter exec unexpectedly returned')
