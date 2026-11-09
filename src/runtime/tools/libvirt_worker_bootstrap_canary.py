"""Qualify worker startup and EOF refusal only; never send a release frame.

The real entry is dormant until explicitly authorized. A one-shot journal binds
original source/interpreter/target FDs and process identity. The target binary is
read, never executed by this recipe. No provisioning or account changes.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import uuid

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_commands import reference_proof
from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
from dnlab_runtime.libvirt_account_runner import open_resource,source_proof,worker_argv,ready_line,collect_output
from dnlab_runtime.libvirt_account_worker import binary_proof,validate_command,ENVIRONMENT,MAX_FRAME
from dnlab_runtime.manifest import Conflict,canonical,fingerprint

REFUSAL='dnlab_runtime.manifest.Conflict: bounded complete worker frame required\n'


def run(journal,command,profile,*,observer,spawn=subprocess.Popen,opener=open_resource,
        read_ready=ready_line,read_output=collect_output):
    validate_command(command)
    token=uuid.uuid4().hex
    packet=(canonical(dict(token=token,command=command))+'\n').encode()
    if len(packet)>MAX_FRAME:raise Conflict('bootstrap request exceeds frame bound')
    value=dict(token=token,phase='prepared',command=deepcopy(command),profile=deepcopy(profile),
        reference=None,release_sent=False,cleanup_verified=False,qualified=False)
    with journal.transaction():
        journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_worker_bootstrap_canaries '
            '(token TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        if journal.db.execute('SELECT token FROM libvirt_worker_bootstrap_canaries').fetchone():
            raise Conflict('bootstrap canary is one-shot; no second worker')
        journal.db.execute('INSERT INTO libvirt_worker_bootstrap_canaries VALUES(?,?)',(token,canonical(value)))
    def save(phase,**updates):
        value.update(phase=phase,**updates)
        with journal.transaction():
            journal.db.execute('UPDATE libvirt_worker_bootstrap_canaries SET payload=? WHERE token=?',
                (canonical(value),token))
    process=None;primary_error=None
    try:
        with opener(command['binary']['path']) as binary,opener(profile['python']['path']) as python,opener(profile['worker']['path']) as worker:
            binary_proof(binary,command['binary']['sha256'])
            binary_proof(python,profile['python']['sha256']);source_proof(worker,profile['worker']['sha256'])
            argv=worker_argv(profile,binary,python,worker)
            save('launch_requested',argv=argv)
            process=spawn(argv,executable='/proc/self/fd/'+str(python),pass_fds=(binary,python,worker),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=deepcopy(ENVIRONMENT),cwd='/',close_fds=True)
            process.stdin.write(packet);process.stdin.flush()
            ready=read_ready(process)
            save('ready_observed',ready=ready)
            if ready!=dict(ready=token,command_sha256=fingerprint(command)):
                raise Conflict('original bootstrap worker readiness differs')
            record=observer.capture(process)
            reference=dict(token=token,command_sha256=fingerprint(command),process_record=record)
            reference_proof(reference,command)
            if record['pid']!=process.pid or record['executable_sha256']!=profile['python']['sha256']:
                raise Conflict('original bootstrap worker process differs')
            observer.bind(reference,process,command);save('armed',reference=reference,ready=ready)
            if observer.verify(reference,process,command,'armed') is not True:
                raise Conflict('original bootstrap worker not qualified')
            save('eof_requested')
            if observer.verify(reference,process,command,'armed') is not True:
                raise Conflict('original bootstrap worker differs before EOF')
            # No release packet is ever constructed or written.
            process.stdin.close()
            result=read_output(process,dict(stdout=b'',stderr=b'',eof=set()))
            if result is None:raise Conflict('worker EOF refusal outcome still pending')
            save('outcome_observed',outcome=result)
            if (set(result)!={'exit_code','stdout','stderr'} or type(result['exit_code']) is not int
                    or result['exit_code']!=1 or result['stdout']!=''
                    or not isinstance(result['stderr'],str) or len(result['stderr'].encode())>65536
                    or not result['stderr'].startswith('Traceback (most recent call last):\n')
                    or not result['stderr'].endswith(REFUSAL)):
                raise Conflict('worker EOF refusal differs')
            if process.wait(timeout=12)!=result['exit_code'] or observer.exit(process,reference) is not True:
                raise Conflict('original worker EOF exit unqualified')
            save('completed',qualified=True,cleanup_verified=True)
            observer.retire(reference)
            return deepcopy(value)
    except BaseException as error:
        primary_error=error
        save('pending',error=dict(type=type(error).__name__,message=str(error)))
        raise
    finally:
        cleanup_errors=[];exceptions=[]
        def attempt(step,action):
            try:action()
            except BaseException as error:
                exceptions.append(error)
                cleanup_errors.append(dict(step=step,type=type(error).__name__,message=str(error)))
        if process is not None:
            if not process.stdin.closed:attempt('stdin_close',process.stdin.close)
            waited={}
            def original_wait():waited['exit_code']=process.wait(timeout=12)
            attempt('original_wait',original_wait)
            if primary_error is not None and 'outcome' not in value and 'exit_code' in waited:
                def capture_diagnostic():
                    diagnostic=read_output(process,dict(stdout=b'',stderr=b'',eof=set()))
                    save('pending',cleanup_outcome=diagnostic)
                attempt('outcome_diagnostic',capture_diagnostic)
            attempt('stdout_close',process.stdout.close)
            attempt('stderr_close',process.stderr.close)
        attempt('observer_close',observer.close)
        if cleanup_errors:
            save('pending',cleanup_verified=False,qualified=False,cleanup_errors=cleanup_errors)
            # Cleanup must never replace the original readiness/protocol error.
            if primary_error is None:raise exceptions[0]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--request',required=True)
    parser.add_argument('--profile',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    if not args.execute:parser.error('worker execution requires --execute')
    output=Path(args.output);output.mkdir(mode=0o700,parents=False,exist_ok=False)
    journal=Journal(output/'journal');observer=AccountWorkerObserver(journal)
    try:
        result=run(journal,json.loads(Path(args.request).read_text()),json.loads(Path(args.profile).read_text()),observer=observer)
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    finally:journal.close()


if __name__=='__main__':main()
