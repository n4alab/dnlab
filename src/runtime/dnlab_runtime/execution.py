"""One reentrant kernel-operation gate per local runtime journal."""
import fcntl
import os
from pathlib import Path
import stat
import threading

from .manifest import Conflict

class ExecutionBusy(Conflict):
    status=503


_REGISTRY={}
_REGISTRY_LOCK=threading.Lock()


class Gate:
    def __init__(self,path):self.path=path;self.mutex=threading.RLock();self.local=threading.local();self.fd=None
    def __enter__(self):
        self.mutex.acquire()
        try:
            depth=getattr(self.local,'depth',0)
            if not depth:
                fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
                try:
                    info=os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                        raise Conflict('runtime execution lock ownership differs')
                    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:raise ExecutionBusy('another runtime process is executing an operation') from None
                except BaseException:os.close(fd);raise
                self.local.fd=fd;self.fd=fd
            self.local.depth=depth+1
            return self
        except BaseException:self.mutex.release();raise
    def __exit__(self,*args):
        self.local.depth-=1
        if not self.local.depth:os.close(self.local.fd);self.fd=None
        self.mutex.release()


def execution_gate(directory):
    path=Path(directory).resolve()/'workload.lock'
    with _REGISTRY_LOCK:return _REGISTRY.setdefault(str(path),Gate(path))


def _after_fork():
    global _REGISTRY_LOCK
    _REGISTRY_LOCK=threading.Lock()
    for gate in _REGISTRY.values():
        if gate.fd is not None:
            os.close(gate.fd);gate.fd=None
        gate.mutex=threading.RLock();gate.local=threading.local()


os.register_at_fork(after_in_child=_after_fork)
