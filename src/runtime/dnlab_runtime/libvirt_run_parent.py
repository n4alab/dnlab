"""Explicit current-boot identity of the volatile OS parent /run.

This is an OS dependency, never a dNLab directory birth or daemon readiness
proof. No observer or filesystem operation is supplied by this module.
"""
from copy import deepcopy
from pathlib import PurePosixPath

from .manifest import Conflict,fingerprint


def run_parent_identity(value):
    if (not isinstance(value,dict) or set(value)!={'device','inode','uid','gid','mode'}
            or any(type(number) is not int for number in value.values())
            or value['device']<=0 or value['inode']<=0
            or (value['uid'],value['gid'],value['mode'])!=(0,0,0o755)):
        raise Conflict('current /run parent must have a pinned root-owned 0755 identity')
    return deepcopy(value)


def validate_run_parent(value,installation,current):
    from .libvirt_postboot import context,plan

    current=context(current);plan(installation,current)
    runtime=PurePosixPath(installation['profile']['session']['runtime_root'])
    original=installation['prerequisites'].get('os_parents',{}).get('/run')
    run_parent_identity(original)
    if (not runtime.is_relative_to('/run') or runtime==PurePosixPath('/run')
            or not isinstance(value,dict) or set(value)!={'kind','path','source_sha256','context','identity'}
            or value['kind']!='current-boot-run-parent-v1' or value['path']!='/run'
            or value['source_sha256']!=fingerprint(installation) or value['context']!=current):
        raise Conflict('original current-boot /run parent binding differs')
    run_parent_identity(value['identity'])
    return deepcopy(value)


def bind_run_parent(installation,current,identity):
    """Prepare an explicit request; fresh full observations must qualify it."""
    return validate_run_parent(dict(kind='current-boot-run-parent-v1',path='/run',
        source_sha256=fingerprint(installation),context=deepcopy(current),
        identity=run_parent_identity(identity)),installation,current)
