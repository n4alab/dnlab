"""Readonly systemctl/procfs observers for the session installation phase.

The command transport is mandatory and injected; importing or constructing does
not execute a command or scan procfs. No signals or service mutations are used.
Process census is only a blocker for candidate UID/GID, never process ownership.
"""
from copy import deepcopy
import os
from pathlib import Path
import re

from dnlab_runtime.manifest import Conflict
from tools.vm_host_inventory import regular


def parse_units(raw,names):
    if not isinstance(raw,str) or len(raw.encode())>65536:raise Conflict('bounded systemctl properties required')
    units={}
    for block in raw.strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            if not sep or key not in ('Id','LoadState','ActiveState','Job') or key in values:
                raise Conflict('systemctl property response malformed or duplicate')
            values[key]=value
        if set(values)!={'Id','LoadState','ActiveState','Job'} or values['Id'] not in names or values['Id'] in units:
            raise Conflict('systemctl unit inventory differs or is ambiguous')
        if values['LoadState'] not in ('loaded','masked','not-found'):
            raise Conflict('systemctl unit load state is unqualified')
        job=values['Job']
        # systemd v257 prints an empty Job property for no job under --all.
        if job and (not re.fullmatch(r'[1-9][0-9]{0,9}',job) or int(job)>=2**32):
            raise Conflict('systemctl job property is unqualified')
        units[values['Id']]=dict(active_state=values['ActiveState'],job_id=int(job) if job else 0)
    if set(units)!=set(names):raise Conflict('systemctl unit observation incomplete')
    return units


class InstallationActivity:
    def __init__(self,profile,*,query,proc_root='/proc',systemctl='/usr/bin/systemctl'):
        self.profile=deepcopy(profile);self.query=query;self.proc_root=Path(proc_root);self.systemctl=systemctl
        if not callable(query) or systemctl!='/usr/bin/systemctl' or not self.proc_root.is_absolute():
            raise Conflict('explicit readonly installation activity transport required')
        self.diagnostics=[]

    def namespaces(self):
        spaces={}
        for name in ('pid','mnt','net','user'):
            info=os.stat(self.proc_root/'self/ns'/name)
            spaces[name]=dict(device=info.st_dev,inode=info.st_ino)
        return spaces

    def processes(self):
        uid=self.profile['session']['uid'];gid=self.profile['session']['gid'];matches=[]
        root=os.open(self.proc_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            names=os.listdir(root)
            if len(names)>65536:raise Conflict('procfs census exceeds bound')
            for name in sorted(names):
                if not name.isascii() or not name.isdecimal() or not 0<int(name)<2**31:continue
                try:raw=regular(root,name+'/status',65536)
                except FileNotFoundError:continue
                credentials={}
                for line in raw.splitlines():
                    key,sep,value=line.partition(b':')
                    if sep and key in (b'Uid',b'Gid',b'Groups'):
                        if key in credentials:raise Conflict('proc credentials duplicated')
                        try:credentials[key]=[int(v) for v in value.split()]
                        except ValueError as error:raise Conflict('proc credentials malformed') from error
                if (set(credentials)!={b'Uid',b'Gid',b'Groups'} or len(credentials[b'Uid'])!=4 or len(credentials[b'Gid'])!=4
                        or any(n<0 for values in credentials.values() for n in values)):
                    raise Conflict('proc credentials incomplete')
                if uid in credentials[b'Uid'] or gid in credentials[b'Gid']+credentials[b'Groups']:
                    matches.append(dict(pid=int(name),uids=credentials[b'Uid'],gids=credentials[b'Gid'],groups=credentials[b'Groups']))
            return matches
        finally:os.close(root)

    def __call__(self):
        names=self.profile['service_order']+self.profile['forbidden_vendor_activation']
        argv=[self.systemctl,'show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',*names]
        environment=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LC_ALL='C',LANG='C',
            SYSTEMD_PAGER='cat',SYSTEMD_COLORS='0',SYSTEMD_LOG_COLOR='0')
        response=self.query(argv,env=environment,timeout=5)
        self.diagnostics.append(dict(argv=argv,response=deepcopy(response)))
        if (not isinstance(response,dict) or set(response)!={'exit_code','stdout','stderr'}
                or type(response['exit_code']) is not int or response['exit_code']!=0
                or not isinstance(response['stdout'],str) or not isinstance(response['stderr'],str)
                or len(response['stdout'].encode())>65536 or response['stderr']!=''):
            raise Conflict('original systemctl readonly query failed or is incomplete')
        observed=dict(units=parse_units(response['stdout'],names),dedicated_uid=self.profile['session']['uid'],processes=self.processes())
        self.diagnostics[-1]['observation']=deepcopy(observed)
        return observed
