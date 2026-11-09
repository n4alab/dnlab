"""Prepare package facts, never an install plan or authorization to install.

Host mode performs one apt-cache policy query with persistent cache files
disabled. It never invokes apt-get, downloads, dpkg actions or systemctl.
Synthetic mode requires a policy fixture and cannot query the host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vm_bundle import unique_pairs
from tools.vm_host_inventory import regular, probe

PACKAGES = ('libvirt0', 'libvirt-daemon', 'libvirt-daemon-driver-qemu',
            'libvirt-daemon-log', 'libvirt-daemon-lock', 'libvirt-clients',
            'python3-libvirt', 'qemu-system-x86', 'qemu-utils', 'ovmf', 'systemd')
COMMAND = ['/usr/bin/apt-cache', '-o', 'Dir::Cache::pkgcache=', '-o',
           'Dir::Cache::srcpkgcache=', 'policy', *PACKAGES]


def distribution(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        key, sep, value = line.partition('=')
        if not sep or key not in ('ID', 'ID_LIKE', 'VERSION_ID', 'VERSION_CODENAME'):continue
        if key in result:raise Conflict('duplicate distribution field: ' + key)
        words = shlex.split(value, comments=True, posix=True)
        if len(words) != 1 or not re.fullmatch(r'[A-Za-z0-9._ -]+', words[0]):
            raise Conflict('distribution field is not a simple value: ' + key)
        result[key] = words[0]
    if not result.get('ID'):raise Conflict('distribution ID missing')
    return result


def installed(raw):
    result = []; seen = set()
    for paragraph in raw.decode('utf-8').split('\n\n'):
        fields = {}
        for line in paragraph.splitlines():
            if line[:1].isspace():continue
            key, sep, value = line.partition(':')
            if sep and key in ('Package', 'Architecture', 'Version', 'Status'):
                if key in fields:raise Conflict('duplicate package status field: ' + key)
                fields[key] = value.strip()
        if fields.get('Package') not in PACKAGES:continue
        if set(fields) != {'Package','Architecture','Version','Status'}:
            raise Conflict('incomplete package status record')
        identity = (fields['Package'], fields['Architecture'])
        if identity in seen:raise Conflict('duplicate package status identity')
        seen.add(identity); result.append(fields)
    return sorted(result, key=lambda value:(value['Package'],value['Architecture']))


def policy(raw):
    result = {}; current = None
    for line in raw.splitlines():
        match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?):', line)
        if match:
            current = match[1]
            if current.split(':',1)[0] not in PACKAGES or current in result:
                raise Conflict('unexpected or duplicate package policy header')
            result[current] = {}
        elif line.strip().startswith(('Installed:', 'Candidate:')):
            if current is None:raise Conflict('package policy field without header')
            key, value = line.strip().split(':',1);value=value.strip()
            if key in result[current] or not value:raise Conflict('ambiguous package policy value')
            result[current][key] = value
    if any(set(row) != {'Installed','Candidate'} for row in result.values()):
        raise Conflict('incomplete package policy block')
    return result


def host_query(command):
    if command != COMMAND:raise Conflict('only the fixed package policy query is allowed')
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}, cwd='/')
    return {'returncode':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr}


def collect(root, prerequisites, query):
    if prerequisites.get('status') != 'collected' or prerequisites.get('qualified') is not False:
        raise Conflict('original prerequisite collection required')
    expected = prerequisites['paths']['usr/lib/os-release']
    if expected.get('kind') != 'regular' or not expected.get('sha256'):
        raise Conflict('original regular distribution file proof required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        boot = regular(fd,'proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
        if boot != prerequisites['boot_id']:raise Conflict('original prerequisite boot differs')
        release = regular(fd,'usr/lib/os-release',16384)
        if hashlib.sha256(release).hexdigest() != expected['sha256']:raise Conflict('original distribution source differs')
        facts = distribution(release)
        base = {'qualified':False,'host_id':prerequisites['host_id'],'boot_id':boot,'distribution':facts}
        if facts['ID'] not in ('debian','ubuntu'):
            return {**base,'status':'unsupported-distribution','query_performed':False}
        status = regular(fd,'var/lib/dpkg/status',64*1024*1024)
        packages = installed(status)
        binary = probe(fd,'usr/bin/apt-cache',content=True,limit=16*1024*1024)
        if binary.get('kind') != 'regular':raise Conflict('regular apt-cache binary required')
        result = query(list(COMMAND))
        if (type(result.get('returncode')) is not int or not isinstance(result.get('stdout'),str)
                or not isinstance(result.get('stderr'),str)):
            raise Conflict('structured package query result required')
        if len(result['stdout'].encode()) + len(result['stderr'].encode()) > 4*1024*1024:
            raise Conflict('package policy output exceeds bound')
        if (regular(fd,'var/lib/dpkg/status',64*1024*1024) != status
                or regular(fd,'usr/lib/os-release',16384) != release
                or regular(fd,'proc/sys/kernel/random/boot_id',128).decode('ascii').strip() != boot
                or probe(fd,'usr/bin/apt-cache',content=True,limit=16*1024*1024) != binary):
            raise Conflict('package inventory inputs changed during query')
        versions = policy(result['stdout']) if result['returncode'] == 0 else None
        return {**base,'status':'collected' if versions is not None else 'query-failed','query_performed':True,
            'installed':packages,'policy':versions,'query':{'argv':list(COMMAND),**result},
            'dpkg_status_sha256':hashlib.sha256(status).hexdigest(),'apt_cache':binary,
            'unresolved':sorted(set(PACKAGES)-{name.split(':',1)[0] for name in (versions or {})}),
            'limitations':['Local cache may be stale; no update/download/install performed',
                'No dependency simulation or maintainer-script/service-hook inspection performed',
                'No daemon, VM, device, network or account operations; no operational qualification']}
    finally:os.close(fd)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--collect-host',action='store_true');source.add_argument('--fixture-root',type=Path)
    parser.add_argument('--prerequisites',required=True,type=Path)
    parser.add_argument('--policy-fixture',type=Path)
    args=parser.parse_args(argv)
    if args.collect_host and args.policy_fixture:parser.error('host mode cannot use policy fixtures')
    if not args.collect_host and (args.fixture_root.resolve()==Path('/') or not args.policy_fixture):
        parser.error('synthetic mode requires a non-host root and policy fixture')
    try:
        raw=args.prerequisites.read_bytes()
        if len(raw)>1024*1024:raise Conflict('prerequisite report exceeds bound')
        original=json.loads(raw,object_pairs_hook=unique_pairs)
        if args.collect_host:query=host_query
        else:
            fixture=json.loads(args.policy_fixture.read_text(),object_pairs_hook=unique_pairs)
            query=lambda command:fixture
        result=collect(Path('/') if args.collect_host else args.fixture_root,original,query)
    except Exception as error:
        print(json.dumps({'status':'incomplete','qualified':False,'error_type':type(error).__name__,'error':str(error)}))
        return 1
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['status']=='collected' else 1


if __name__ == '__main__':
    raise SystemExit(main())
