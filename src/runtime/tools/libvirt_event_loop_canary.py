"""One-shot loop-only qualification inside a dedicated canary process.

Preparation/import does not start a thread. The externally qualified caller
supplies the original runtime witness, SDK and scope preflight. This function
never opens a hypervisor connection, starts a subprocess, signals or creates a
domain. It leaves the retired dispatcher running until process exit; the parent
must qualify that original process's exit before declaring cleanup complete.
"""
from copy import deepcopy
import time
import uuid

from dnlab_runtime.libvirt_event_loop import LibvirtEventLoop
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import fields, require


def run(runtime, sdk, *, preflight, loop_factory=LibvirtEventLoop,
        clock=time.monotonic, pause=time.sleep, timeout=5):
    require(callable(preflight) and callable(loop_factory) and callable(clock) and callable(pause)
            and type(timeout) in (int,float) and 0<timeout<=10, 'explicit bounded loop-only canary providers required')
    journal=runtime.journal;epoch=runtime.check()
    expected=dict(purpose='isolated-libvirt-loop-canary',runtime_epoch_sha256=fingerprint(epoch),
                  hypervisor_connections_allowed=False,domain_actions_allowed=False)
    def check_scope():
        require(runtime.check()==epoch and preflight()==expected, 'original isolated canary process scope differs')
    check_scope()
    value=dict(id=uuid.uuid4().hex,epoch_sha256=fingerprint(epoch),phase='prepared',
               loop_sha256=None,retirement=None,qualified=False,cleanup_verified=False,
               requires_original_process_exit=True,gate_allowed=False,error=None)
    with journal.execution_lock:
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_event_loop_canaries '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            require(journal.db.execute('SELECT 1 FROM libvirt_event_loop_canaries').fetchone() is None,
                    'loop canary journal is one-shot; no second dispatch attempt')
            tables={row[0] for row in journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'vm_libvirt_event_loops' in tables:
                require(journal.db.execute('SELECT 1 FROM vm_libvirt_event_loops').fetchone() is None,
                        'canary requires a fresh runtime without an existing loop')
            journal.db.execute('INSERT INTO libvirt_event_loop_canaries VALUES(?,?,?)',
                (value['id'],canonical(value),fingerprint(value)))
    def save(phase, **updates):
        value.update(phase=phase,**updates)
        with journal.transaction():
            journal.db.execute('UPDATE libvirt_event_loop_canaries SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))
    try:
        check_scope();save('start_requested');check_scope()
        loop=loop_factory(runtime,sdk)
        original=loop.start();check_scope()
        require(loop.sdk is sdk and loop.check()==original, 'original canary SDK loop differs')
        save('running',loop_sha256=original)
        initial=loop.iterations;deadline=clock()+timeout
        while loop.iterations<=initial:
            check_scope();require(loop.check()==original, 'original canary loop receipt changed')
            require(clock()<deadline, 'canary loop progress deadline exceeded')
            pause(min(0.01,max(0,deadline-clock())))
        check_scope();require(loop.check()==original, 'original canary loop changed before retirement')
        save('retire_requested')
        check_scope();retired=loop.retire()
        fields(retired,('id','epoch_id','epoch_sha256','configuration_sha256','phase','timer','thread_id'), 'canary loop retirement')
        require(retired['phase']=='retired' and retired['epoch_sha256']==fingerprint(epoch), 'original loop retirement differs')
        save('retired',retirement=deepcopy(retired))
        check_scope()
        # This is dispatch qualification, never a process-exit/cleanup receipt.
        save('awaiting_process_exit',qualified=True)
        return deepcopy(value)
    except BaseException as error:
        save('pending',qualified=False,error=dict(type=type(error).__name__,message=str(error)))
        raise
