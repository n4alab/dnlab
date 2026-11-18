"""Readonly original terminal job metadata/logs across image-build stop/start.

Host paths/identities must be qualified against the original Docker mounts by
the caller. Payload source/log paths are data; no path from a job is followed.
Capture is explicit before the gate, not learning during held-state checks.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

from dnlab_runtime.libvirt_xml import absolute
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_bundle import metadata, unique_pairs
from dnlab_runtime.vm_template import digest, fields, require
from dnlab_runtime.image_build_hold import actor
from image_build_observation import terminal_jobs_digest

DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
JOB_FIELDS = ('id','kind','source_path','with_persistence','generic_spec','created_at',
              'started_at','finished_at','status','returncode')
MAX_LOG = 256*1024*1024
MAX_TOTAL = 1024*1024*1024


def identity(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))


def _directory(stack, path, expected):
    fd = os.open('/',DIRECTORY);stack.callback(os.close,fd)
    for part in PurePosixPath(path).parts[1:]:
        fd = os.open(part,DIRECTORY,dir_fd=fd);stack.callback(os.close,fd)
    info = os.fstat(fd)
    require(identity(info)==expected and info.st_uid==0 and not info.st_mode&0o022,
            'original root-controlled job ledger directory required')
    return fd


def _file(parent, name, limit, *, content=False):
    with ExitStack() as stack:
        pin = os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,pin)
        info = os.fstat(pin)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0
                and not info.st_mode&0o022 and info.st_size<=limit, 'bounded original regular job ledger asset required')
        fd = os.open('/proc/self/fd/'+str(pin),os.O_RDONLY|os.O_CLOEXEC);stack.callback(os.close,fd)
        before = metadata(info);hashed = hashlib.sha256();size = 0;blocks = []
        while True:
            chunk = os.read(fd,min(1024*1024,limit+1-size))
            if not chunk:break
            size += len(chunk);require(size<=limit, 'job ledger asset grew beyond bound')
            hashed.update(chunk)
            if content:blocks.append(chunk)
        require(size==info.st_size and metadata(os.fstat(fd))==before
                and metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))==before,
                'job ledger asset changed during read')
        return dict(metadata=list(before),sha256=hashed.hexdigest()),b''.join(blocks)


def _scan(profile, read_context):
    require(read_context()==profile['context'], 'original job ledger context differs')
    with ExitStack() as stack:
        roots = {role:_directory(stack,profile['paths'][role],profile['identities'][role]) for role in ('jobs','logs')}
        before = {role:metadata(os.fstat(fd)) for role,fd in roots.items()}
        names = {role:sorted(os.listdir(fd)) for role,fd in roots.items()}
        require(sum(map(len,names.values()))<=8192, 'bounded original job ledger inventory required')
        records = profile['records']
        require(names['jobs']==sorted(record['metadata']['id']+'.json' for record in records),
                'job ledger inventory differs from original API jobs')
        require(all(re.fullmatch('[0-9a-f]{16}\\.log',name) for name in names['logs']), 'unknown job log entry')
        assets = {};total = 0
        for record in records:
            expected = record['metadata'];name = expected['id']+'.json'
            proof,raw = _file(roots['jobs'],name,min(1024*1024,MAX_TOTAL-total),content=True)
            require(json.loads(raw,object_pairs_hook=unique_pairs)==expected, 'original API job metadata differs from ledger')
            assets['jobs/'+name]=proof;total += proof['metadata'][5]
            require(total<=MAX_TOTAL, 'job ledger total exceeds bound')
            require(expected['id']+'.log' in names['logs'] or record['empty_api_log'], 'original API log missing from ledger')
        for name in names['logs']:
            proof,_ = _file(roots['logs'],name,min(MAX_LOG,MAX_TOTAL-total))
            assets['logs/'+name]=proof;total += proof['metadata'][5]
            require(total<=MAX_TOTAL, 'job ledger total exceeds bound')
        # Recheck earlier files after later hashes, plus the same directory and
        # inventory through both pinned descriptors and visible original paths.
        for key,proof in assets.items():
            role,name = key.split('/',1)
            require(list(metadata(os.stat(name,dir_fd=roots[role],follow_symlinks=False)))==proof['metadata'],
                    'job ledger asset replaced during set observation')
        for role,fd in roots.items():
            require(metadata(os.fstat(fd))==before[role] and sorted(os.listdir(fd))==names[role],
                    'job ledger directory/inventory changed')
            visible = _directory(stack,profile['paths'][role],profile['identities'][role])
            require(metadata(os.fstat(visible))==before[role],
                    'original job ledger directory path replaced')
        require(read_context()==profile['context'], 'job ledger context changed during read')
        return dict(directories={role:list(value) for role,value in before.items()},assets=assets)


def capture_ledger(*, paths, identities, container_log_dir, api_jobs, original_actor, context, read_context):
    fields(paths,('jobs','logs'),'original host job ledger paths')
    fields(identities,('jobs','logs'),'original job ledger identities')
    for value in identities.values():
        fields(value,('device','inode','uid','gid','mode'),'original ledger directory identity')
        require(all(type(v) is int and v>=0 for v in value.values()) and value['inode']>0,
                'original ledger directory identity required')
    actor(original_actor)
    require(original_actor['context_sha256']==fingerprint(context), 'original job ledger actor context differs')
    for path in paths.values():absolute(path)
    absolute(container_log_dir)
    require(not PurePosixPath(paths['jobs']).is_relative_to(paths['logs'])
            and not PurePosixPath(paths['logs']).is_relative_to(paths['jobs']), 'distinct original metadata/log trees required')
    jobs_sha256 = terminal_jobs_digest(api_jobs)
    records = []
    for job in sorted(api_jobs,key=lambda value:value['id']):
        require(all(key in job for key in JOB_FIELDS) and type(job.get('log')) is list,
                'complete original API job metadata/log projection required')
        payload = {key:deepcopy(job[key]) for key in JOB_FIELDS}
        payload['log_path']=str(PurePosixPath(container_log_dir)/(job['id']+'.log'))
        records.append(dict(metadata=payload,empty_api_log=not job['log']))
    profile = dict(paths=deepcopy(paths),identities=deepcopy(identities),records=records,
                   actor_sha256=fingerprint(original_actor),context=deepcopy(context),jobs_sha256=jobs_sha256)
    first = _scan(profile,read_context);second = _scan(profile,read_context)
    require(first==second, 'job ledger changed during original capture')
    return dict(profile=profile,evidence=first)


class JobLedger:
    def __init__(self, receipt, *, expected_sha256, read_context):
        fields(receipt,('profile','evidence'),'original job ledger receipt')
        require(digest(expected_sha256) and fingerprint(receipt)==expected_sha256 and callable(read_context),
                'original job ledger binding and context reader required')
        self.receipt,self.sha256,self.read_context = deepcopy(receipt),expected_sha256,read_context

    def __call__(self, value):
        require(fingerprint(self.receipt)==self.sha256, 'original job ledger capability changed')
        profile = self.receipt['profile']
        require(fingerprint(value['actor'])==profile['actor_sha256'] and value['jobs_sha256']==profile['jobs_sha256'],
                'original image-build ledger owner/jobs differ')
        require(_scan(profile,self.read_context)==self.receipt['evidence'], 'original job metadata/log history changed')
        return dict(ledger_sha256=self.sha256,jobs_sha256=profile['jobs_sha256'])
