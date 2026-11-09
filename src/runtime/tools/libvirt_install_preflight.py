"""Readonly preparation snapshot; never executes account or service commands.

This does not qualify live systemd/process state, NSS identities, device access
or the provisioning window. Host collection requires an explicit CLI switch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict, fingerprint
from tools.vm_host_inventory import regular, probe


def accounts(raw,kind):
    result=[];seen=set();width=7 if kind=='account' else 4
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):continue
        fields=line.split(':')
        if len(fields)!=width or not fields[0] or fields[0] in seen or not fields[2].isdecimal():
            raise Conflict('ambiguous local '+kind+' database')
        seen.add(fields[0])
        if kind=='account':
            if not fields[3].isdecimal():raise Conflict('local account GID malformed')
            result.append(dict(name=fields[0],uid=int(fields[2]),gid=int(fields[3])))
        else:result.append(dict(name=fields[0],gid=int(fields[2])))
    return result


def packages(raw,expected):
    result={}
    for paragraph in raw.decode('utf-8').split('\n\n'):
        values={}
        for line in paragraph.splitlines():
            if line[:1].isspace():continue
            key,sep,value=line.partition(':')
            if sep and key in ('Package','Version','Status','Architecture'):
                if key in values:raise Conflict('ambiguous package record')
                values[key]=value.strip()
        name=values.get('Package')
        if name not in expected:continue
        if name in result or set(values)!={'Package','Version','Status','Architecture'}:
            raise Conflict('ambiguous expected package identity')
        result[name]=values
    return result


def collect(root,request,expected_packages):
    profile=render_profile(**request)
    if not isinstance(expected_packages,dict) or not expected_packages or any(
            not isinstance(k,str) or not isinstance(v,str) or not k or not v for k,v in expected_packages.items()):
        raise Conflict('explicit installed package versions required')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    def snapshot():
        raw={path:regular(fd,path,32*1024*1024 if path.endswith('/status') else 1024*1024)
             for path in ('proc/sys/kernel/random/boot_id','etc/passwd','etc/group','var/lib/dpkg/status')}
        boot=raw['proc/sys/kernel/random/boot_id'].decode('ascii').strip()
        if not boot:raise Conflict('host boot identity missing')
        paths={}
        for binary in profile['binaries'].values():
            path=binary['path'];paths[path]=probe(fd,path.lstrip('/'),content=True,limit=128*1024*1024)
        for name in profile['forbidden_vendor_activation']:
            path='/etc/systemd/system/'+name;paths[path]=probe(fd,path.lstrip('/'))
        for item in profile['directories']:
            path=item['path'];paths[path]=probe(fd,path.lstrip('/'))
        for path in profile['files']:paths[path]=probe(fd,path.lstrip('/'),content=True)
        return dict(boot_id=boot,source_sha256={p:hashlib.sha256(v).hexdigest() for p,v in raw.items()},
            local_accounts=accounts(raw['etc/passwd'],'account'),local_groups=accounts(raw['etc/group'],'group'),
            packages=packages(raw['var/lib/dpkg/status'],expected_packages),paths=paths)
    try:
        observed=snapshot();recheck=snapshot()
        if observed!=recheck:raise Conflict('installation preflight changed during collection')
    finally:os.close(fd)
    candidate=profile['account']
    account_conflicts=[row for row in observed['local_accounts'] if row['name']==candidate['name'] or row['uid']==candidate['uid']]
    group_conflicts=[row for row in observed['local_groups'] if row['name']==candidate['group'] or row['gid']==candidate['gid']]
    problems=[]
    if account_conflicts:problems.append('dedicated account name or UID occupied')
    if group_conflicts:problems.append('dedicated group name or GID occupied')
    for name,version in expected_packages.items():
        value=observed['packages'].get(name,{})
        if value.get('Version')!=version or value.get('Status')!='install ok installed':
            problems.append('installed package differs: '+name)
    for value in profile['binaries'].values():
        found=observed['paths'][value['path']]
        if found.get('kind')!='regular' or found.get('sha256')!=value['sha256']:
            problems.append('daemon executable differs: '+value['path'])
    for name in profile['forbidden_vendor_activation']:
        path='/etc/systemd/system/'+name;found=observed['paths'][path]
        if found.get('kind')!='symlink' or found.get('target')!='/dev/null':
            problems.append('vendor administrative mask differs: '+path)
    # Existing target paths are never silently adopted. Their explicit dependency
    # qualification belongs to a separately prepared installation intent.
    occupied=[path for path,value in observed['paths'].items() if value['status']!='absent'
        and (path in profile['files'] or path in {d['path'] for d in profile['directories']})]
    return dict(status='collected',qualified=False,profile_sha256=profile['profile_sha256'],
        observation_sha256=fingerprint(observed),observed=observed,blocking_findings=problems,
        occupied_targets=occupied,account_conflicts=account_conflicts,group_conflicts=group_conflicts,
        limitations=['Local passwd/group only; NSS identity conflicts not qualified',
            'Masks observed as filesystem links; service/process inactivity not qualified',
            'No package/account commands, device or libvirt connections, writes or service actions',
            'No free ID allocation, existing resource adoption or window activation'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default='/');parser.add_argument('--collect-host',action='store_true')
    parser.add_argument('--request',required=True);parser.add_argument('--expected-packages',required=True)
    args=parser.parse_args()
    if Path(args.root).resolve()==Path('/') and not args.collect_host:
        parser.error('host collection requires --collect-host')
    result=collect(args.root,json.loads(Path(args.request).read_text()),json.loads(Path(args.expected_packages).read_text()))
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
