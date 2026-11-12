"""Pinned readonly iproute2 inventory with numeric TAP credentials.

ip link resolves UID/GID names even with -N. ip tuntap show emits numbers;
equal numeric observations surrounding the link dump qualify their correlation.
No name lookup is used as a resource identity or a creation acknowledgement.
"""
from copy import deepcopy
import json
import os
import subprocess

from .libvirt_account_runner import open_resource
from .libvirt_account_worker import ENVIRONMENT, binary_proof
from .manifest import Conflict
from .vm_bundle import unique_pairs
from .vm_tap_device import context as namespace
from .vm_template import digest, fields, require

MAX_OUTPUT=4*1024*1024
LINKS=('-j','-d','link','show')
NUMERIC=('-j','tuntap','show')


def indexed(links):
    require(type(links) is list and 1<=len(links)<=16384, 'bounded complete link inventory required')
    result={};indices=set()
    for link in links:
        require(type(link) is dict and type(link.get('ifindex')) is int and 0<link['ifindex']<2**31
            and isinstance(link.get('ifname'),str) and 0<len(link['ifname'].encode('utf8'))<=15
            and not any(char in link['ifname'] for char in ('\0','/'))
            and link['ifname'] not in result and link['ifindex'] not in indices,
            'unique complete link name/ifindex inventory required')
        result[link['ifname']]=link;indices.add(link['ifindex'])
    return result


def numeric(rows):
    require(type(rows) is list and len(rows)<=16384, 'bounded numeric TUN inventory required')
    result={}
    for row in rows:
        require(type(row) is dict and {'ifname','flags'}<=row.keys()
            and row.keys()<={'ifname','flags','user','group'}, 'numeric TUN inventory fields differ')
        name=row['ifname'];flags=row['flags']
        require(isinstance(name,str) and 0<len(name.encode('utf8'))<=15 and name not in result
            and type(flags) is list and len(flags)<=16
            and all(isinstance(flag,str) and 0<len(flag)<=64 for flag in flags)
            and len(set(flags))==len(flags) and len(set(flags)&{'tun','tap'})==1,
            'unique numeric TUN names/types required')
        require(all(type(row[key]) is int and 0<=row[key]<2**32-1 for key in ('user','group') if key in row),
            'numeric TUN UID/GID required; account names are diagnostic only')
        result[name]=deepcopy(row);result[name]['flags']=sorted(flags)
    return result


def correlate(links, before, after):
    full=indexed(links);before=numeric(before);after=numeric(after)
    if before!=after:raise Conflict('TAP ownership/flags changed during inventory')
    tun={name:link for name,link in full.items() if link.get('linkinfo',{}).get('info_kind')=='tun'}
    require(set(tun)==set(before), 'link/numeric TUN inventory is incomplete or changed')
    result=deepcopy(links)
    for link in result:
        if link['ifname'] not in tun:continue
        row=before[link['ifname']];data=link['linkinfo'].get('info_data')
        require(type(data) is dict and data.get('type') in ('tun','tap') and data['type'] in row['flags'],
            'original TUN type correlation differs')
        for key,flag in (('persist','persist'),('pi','pi'),('vnet_hdr','vnet_hdr')):
            require(type(data.get(key)) is bool and data[key]==(flag in row['flags']),
                'original TUN flag correlation differs')
        for key in ('user','group'):
            require((key in data)==(key in row), 'TUN credentials changed during link observation')
            if key in row:
                require(isinstance(data[key],str) or type(data[key]) is int and data[key]==row[key],
                    'TUN numeric credential correlation differs')
                data[key]=row[key]
    return result


class TapInventory:
    def __init__(self, profile, context, *, read_context, run=subprocess.run, opener=open_resource):
        fields(profile,('path','sha256','identity'),'TAP inventory executable')
        require(profile['path']=='/usr/bin/ip' and digest(profile['sha256'])
            and type(profile['identity']) is list and len(profile['identity'])==8
            and all(type(value) is int and value>=0 for value in profile['identity'])
            and all(callable(fn) for fn in (read_context,run,opener)), 'pinned iproute2 inventory profile required')
        self.profile,self.context=deepcopy(profile),namespace(context)
        self.read_context,self.run,self.opener=read_context,run,opener

    def _scope(self):
        if self.read_context()!=self.context:raise Conflict('original TAP inventory namespace changed')
        current=os.stat('/proc/thread-self/ns/net')
        if (current.st_dev,current.st_ino)!=(self.context['device'],self.context['inode']):
            raise Conflict('inventory thread belongs to another namespace')

    def _binary(self, fd):
        require(list(binary_proof(fd,self.profile['sha256']))==self.profile['identity'],
            'original iproute2 inode/metadata changed')

    def _query(self, fd, arguments):
        require(arguments in (LINKS,NUMERIC), 'fixed readonly TAP query required')
        self._scope();self._binary(fd)
        result=self.run([self.profile['path'],*arguments],executable='/proc/self/fd/'+str(fd),
            pass_fds=(fd,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=deepcopy(ENVIRONMENT),cwd='/',close_fds=True,timeout=5,check=False)
        self._scope();self._binary(fd)
        require(type(result.returncode) is int and result.returncode==0 and result.stderr==b''
            and isinstance(result.stdout,bytes) and 0<len(result.stdout)<=MAX_OUTPUT,
            'complete bounded readonly iproute2 response required')
        try:return json.loads(result.stdout,object_pairs_hook=unique_pairs)
        except (UnicodeError,ValueError) as error:raise Conflict('invalid readonly iproute2 JSON') from error

    def __call__(self):
        self._scope()
        with self.opener(self.profile['path']) as fd:
            before=self._query(fd,NUMERIC);links=self._query(fd,LINKS);after=self._query(fd,NUMERIC)
            value=correlate(links,before,after);self._scope();self._binary(fd)
        self._scope()
        return value
