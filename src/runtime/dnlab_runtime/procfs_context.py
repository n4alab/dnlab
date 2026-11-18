"""Readonly binding of an explicitly qualified procfs to the current caller."""
import os

from .libvirt_account_process import AccountWorkerObserver
from .vm_template import fields, require


def check(proc, *, context, read_context, proc_identity, proc_root):
    fields(context,('host_id','boot_id','namespaces'),'procfs context')
    fields(context['namespaces'],('pid','mnt','net','user'),'procfs namespaces')
    for value in context['namespaces'].values():
        fields(value,('device','inode'),'procfs namespace')
        require(all(type(v) is int and v>0 for v in value.values()), 'original procfs namespace required')
    fields(proc_identity,('device','inode'),'qualified procfs identity')
    require(all(type(v) is int and v>0 for v in proc_identity.values()), 'qualified procfs identity required')
    require(read_context()==context, 'session census calling context differs')
    info=os.fstat(proc)
    require(dict(device=info.st_dev,inode=info.st_ino)==proc_identity, 'qualified session census procfs replaced')
    require(os.readlink('self',dir_fd=proc)==str(os.getpid()), 'session census procfs PID namespace differs')
    boot=AccountWorkerObserver._read_file(proc,'sys/kernel/random/boot_id',128).decode('ascii').strip()
    require(boot==context['boot_id'], 'session census boot differs')
    for name,expected in context['namespaces'].items():
        info=os.stat('self/ns/'+name,dir_fd=proc)
        require(dict(device=info.st_dev,inode=info.st_ino)==expected, 'session census procfs namespace differs')
    visible=os.stat(proc_root,follow_symlinks=False)
    require((visible.st_dev,visible.st_ino)==(proc_identity['device'],proc_identity['inode']),
            'session census procfs path replaced')
