"""Explicit, harmless process-observer canary. No account commands are used.

Preparation/tests do not run this entry point. Execution requires --execute and
an explicit interpreter path/hash. The child only reports readiness, waits for
EOF (at most ten seconds), and exits. No signals, network, Docker or libvirt.
A lost parent leaves the original journal pending; it is never retried/adopted.
"""
from copy import deepcopy
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
from dnlab_runtime.libvirt_account_runner import open_resource,ready_line
from dnlab_runtime.libvirt_account_worker import binary_proof,ENVIRONMENT
from dnlab_runtime.manifest import Conflict,canonical,fingerprint


CHILD="""import json,select,sys
print(json.dumps({'ready':'observer-canary'}),flush=True)
r,_,_=select.select([sys.stdin],[],[],10)
if not r:sys.exit(4)
sys.exit(0 if sys.stdin.buffer.read(1)==b'' else 5)
"""


def run(journal,profile,*,spawn=subprocess.Popen,observer=None,opener=open_resource,read_ready=ready_line):
    if (not isinstance(profile,dict) or set(profile)!={'path','sha256'}
            or not isinstance(profile['path'],str) or not profile['path'].startswith('/')
            or len(profile['sha256'])!=64 or any(c not in '0123456789abcdef' for c in profile['sha256'])):
        raise Conflict('explicit interpreter path and hash required')
    observer=observer or AccountWorkerObserver(journal)
    token=uuid.uuid4().hex
    value=dict(token=token,phase='prepared',profile=deepcopy(profile),reference=None,
        qualified=False,cleanup_verified=False)
    with journal.transaction():
        journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_account_observer_canaries '
            '(token TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        if journal.db.execute('SELECT token FROM libvirt_account_observer_canaries').fetchone():
            raise Conflict('canary journal is one-shot; no second process or adoption')
        journal.db.execute('INSERT INTO libvirt_account_observer_canaries VALUES(?,?)',(token,canonical(value)))
    def save(phase,**updates):
        value.update(phase=phase,**updates)
        with journal.transaction():
            journal.db.execute('UPDATE libvirt_account_observer_canaries SET payload=? WHERE token=?',
                (canonical(value),token))
    process=None
    try:
        with opener(profile['path']) as fd:
            binary_proof(fd,profile['sha256'])
            argv=[profile['path'],'-B','-I','-S','-c',CHILD]
            command=dict(binary=deepcopy(profile),argv=argv,purpose='harmless-observer-canary')
            save('launch_requested')
            process=spawn(argv,executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=deepcopy(ENVIRONMENT),cwd='/',close_fds=True)
            if read_ready(process)!=dict(ready='observer-canary'):raise Conflict('canary readiness differs')
            record=observer.capture(process)
            if record['pid']!=process.pid or record['executable_sha256']!=profile['sha256']:
                raise Conflict('original canary process differs')
            reference=dict(token=token,command_sha256=fingerprint(command),process_record=record)
            observer.bind(reference,process,command)
            save('armed',reference=reference)
            if observer.verify(reference,process,command,'armed') is not True:
                raise Conflict('original canary not qualified')
            save('eof_requested')
            if observer.verify(reference,process,command,'armed') is not True:
                raise Conflict('original canary differs before EOF')
            process.stdin.close()
            status=process.wait(timeout=12)
            if type(status) is not int or status!=0:raise Conflict('canary did not exit successfully on EOF')
            if observer.exit(process,reference) is not True:raise Conflict('original canary exit unqualified')
            if observer.verify(reference,process,command,'completed') is not True:
                raise Conflict('canary durable exit receipt differs')
            save('completed',qualified=True,cleanup_verified=True,exit_code=status)
            observer.retire(reference)
            return deepcopy(value)
    except BaseException as error:
        save('pending',error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        # EOF only; bounded original waiter, never a signal or a replacement child.
        # If proof/exit cannot be obtained, the journal stays pending.
        try:
            if process is not None:
                if not process.stdin.closed:process.stdin.close()
                try:process.wait(timeout=12)
                finally:
                    process.stdout.close();process.stderr.close()
        except BaseException as error:
            save('pending',cleanup_verified=False,cleanup_error=dict(type=type(error).__name__,message=str(error)))
            raise
        finally:observer.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--python',required=True);parser.add_argument('--sha256',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.execute:parser.error('process execution requires --execute')
    output=Path(args.output);output.mkdir(mode=0o700,parents=False,exist_ok=False)
    journal=Journal(output/'journal')
    try:
        result=run(journal,dict(path=args.python,sha256=args.sha256))
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    finally:journal.close()


if __name__=='__main__':main()
