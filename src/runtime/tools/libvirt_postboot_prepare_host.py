"""Explicit metadata-only host prepare; no directory apply or service actions.

Run only from a frozen private recipe after operational authorization. Importing
this module or requesting help does not inspect the installation. Resume uses
the same output, recipe and journal binding; conflicts preserve pending state.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback
import uuid

RUNTIME=Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT=Path('/var/lib/dnlab-runtime-spikes')
INPUTS=('installed.json','journal-reference.json','expected-packages.json','approved-account-inputs.json',
        'worker-profile.json','expected-context.json','postboot.json')
BOUND_INPUTS=INPUTS+('journal-binding.json',)


def verify_recipe(recipe):
    recipe=Path(recipe);receipt=json.loads((recipe/'receipt.json').read_text())
    sources={str(path.relative_to(RUNTIME)) for directory in ('dnlab_runtime','tools')
        for path in (RUNTIME/directory).glob('*.py')}
    if (receipt.get('schema_version')!=1 or receipt.get('runtime_root')!=str(RUNTIME)
            or set(receipt.get('input_sha256',{})) not in (set(INPUTS),set(BOUND_INPUTS)) or not sources
            or set(receipt.get('source_sha256',{}))!=sources
            or receipt.get('entry_sha256')!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise RuntimeError('frozen post-boot prepare recipe differs')
    for name,digest in receipt['source_sha256'].items():
        if hashlib.sha256((RUNTIME/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('post-boot prepare source changed: '+name)
    for name,digest in receipt['input_sha256'].items():
        if hashlib.sha256((recipe/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('post-boot prepare input changed: '+name)
    return receipt


def read_output(fd,name):
    try:file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
    except FileNotFoundError:return None
    try:
        before=os.fstat(file)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>4*1024*1024):
            raise RuntimeError('original prepare output metadata differs: '+name)
        with os.fdopen(os.dup(file),'rb') as stream:raw=stream.read(4*1024*1024+1)
        value=json.loads(raw)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        after=os.fstat(file);visible=os.stat(name,dir_fd=fd,follow_symlinks=False)
        if (len(raw)!=before.st_size or any(getattr(before,key)!=getattr(after,key)
                or getattr(before,key)!=getattr(visible,key) for key in fields)):
            raise RuntimeError('original prepare output changed: '+name)
        os.fsync(file);os.fsync(fd)
        return value
    finally:os.close(file)


def run(recipe,*,resume_output=None):
    recipe=Path(recipe);receipt=verify_recipe(recipe)
    inputs={name:json.loads((recipe/name).read_text()) for name in receipt['input_sha256']}
    installed=inputs['installed.json'];reference=inputs['journal-reference.json']
    expected=inputs['expected-context.json'];request=inputs['postboot.json'];nonce=request['nonce']
    if (set(request)!={'qualification_id','recovery_id','nonce','window','run_parent'}
            or not isinstance(nonce,str) or len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce)):
        raise RuntimeError('explicit post-boot prepare request required')
    sys.path.insert(0,str(RUNTIME))
    from dnlab_runtime.libvirt_account_identity import host_query
    from dnlab_runtime.libvirt_account_runner import open_resource
    from dnlab_runtime.libvirt_account_worker import binary_proof
    from dnlab_runtime.libvirt_postboot import context as validate_context,plan
    from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
    from dnlab_runtime.manifest import identifier
    from tools.libvirt_configuration_prepare import context,save
    from tools.libvirt_postboot_assembly import PostBootPrepareAssembly
    from tools.libvirt_postboot_journal import open_postboot_journal
    from tools.libvirt_postboot_prepare import PrepareDelivery
    validate_context(expected);layout=plan(installed,expected)
    for name in ('qualification_id','recovery_id'):identifier(request[name],name)
    agreement=request['window']
    if (agreement['operation_id']!=request['recovery_id'] or agreement['context']!=expected
            or set(agreement['targets'])!=set(layout['volatile'])):
        raise RuntimeError('separate post-boot directory window differs')
    output=OUTPUT_PARENT/('libvirt-postboot-prepare-'+nonce[:12])
    if resume_output is not None and Path(resume_output)!=output:
        raise RuntimeError('original prepare output required for resume')
    parent=os.open(OUTPUT_PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(parent)
        if info.st_uid!=os.getuid() or info.st_mode&0o022:raise RuntimeError('private prepare output parent differs')
        if resume_output is None:os.mkdir(output.name,mode=0o700,dir_fd=parent);os.fsync(parent)
        output_fd=os.open(output.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    try:
        info=os.fstat(output_fd)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('original private prepare output differs')
        intent=dict(kind='native-postboot-prepare-v1',request=request,expected_context=expected,
            journal_reference=reference,recipe=receipt)
        if resume_output is None:save(output,'invocation.json',intent)
        elif read_output(output_fd,'invocation.json')!=intent:raise RuntimeError('original prepare invocation differs')
        print('Output: '+str(output),flush=True)
        result=dict(status='prepare_requested',qualified=False,scope='metadata-only',started=time.time(),contexts=[])
        assembly=None;queries=[];code=1
        try:
            def verify():
                observed=context(installed);result['contexts'].append(dict(expected=expected,observed=observed))
                if observed!=expected:raise RuntimeError('explicit current prepare context differs')
                visible=os.stat(output,follow_symlinks=False)
                if (visible.st_dev,visible.st_ino)!=(info.st_dev,info.st_ino):raise RuntimeError('original prepare output replaced')
                verify_recipe(recipe)
            verify()
            with ExitStack() as stack:
                executable=stack.enter_context(open_resource('/usr/bin/systemctl'))
                binary_proof(executable,receipt['systemctl_sha256'])
                names=installed['profile']['service_order']+installed['profile']['forbidden_vendor_activation']
                allowed=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',*names]
                def query(argv,*,env,timeout):
                    if argv!=allowed or timeout!=5:raise RuntimeError('readonly prepare query differs')
                    binary_proof(executable,receipt['systemctl_sha256']);entry=dict(argv=argv,status='requested');queries.append(entry)
                    try:
                        completed=subprocess.run(argv,executable='/proc/self/fd/'+str(executable),pass_fds=(executable,),
                            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            env=env,cwd='/',timeout=timeout,check=False)
                    except BaseException as error:
                        entry.update(status='failed',error=dict(type=type(error).__name__,message=str(error)));raise
                    entry.update(status='completed',exit_code=completed.returncode,
                        stdout=completed.stdout.decode('utf-8','replace'),stderr=completed.stderr.decode('utf-8','replace'))
                    return {key:entry[key] for key in ('exit_code','stdout','stderr')}
                window=ProvisioningWindow(agreement,lambda:json.loads((recipe/'postboot.json').read_text())['window'])
                binding=read_output(output_fd,'journal-binding.json') if resume_output is not None else None
                if 'journal-binding.json' in inputs:
                    original_binding=inputs['journal-binding.json']
                    if resume_output is None:save(output,'journal-binding.json',original_binding)
                    elif binding!=original_binding:raise RuntimeError('original retained prepare journal binding differs')
                    binding=original_binding
                journal,_=stack.enter_context(open_postboot_journal(reference['directory'],installed,
                    identity=reference['identity'],initial_sha256=reference['database_sha256'],
                    retain=lambda value:save(output,'journal-binding.json',value),verify=verify,original_binding=binding))
                assembly=PostBootPrepareAssembly(journal,installed,expected,
                    qualification_id=request['qualification_id'],recovery_id=request['recovery_id'],
                    run_parent=request['run_parent'],window=window,expected_packages=inputs['expected-packages.json'],
                    approved_account_inputs=inputs['approved-account-inputs.json'],worker_profile=inputs['worker-profile.json'],
                    query=query,nss_query=host_query)
                with PrepareDelivery(assembly.session,output_fd) as delivery:
                    prepared=delivery.prepare(resume=resume_output is not None)
                verify();binary_proof(executable,receipt['systemctl_sha256'])
                result.update(status='prepared',qualification_id=request['qualification_id'],recovery_id=request['recovery_id'],
                    phase=prepared['recovery']['phase']);code=0
        except BaseException as error:
            result.update(status='failed',error=dict(type=type(error).__name__,message=str(error)),traceback=traceback.format_exc())
        finally:
            if assembly is not None:result['diagnostics']=assembly.diagnostics
            result.update(queries=queries,finished=time.time(),exit_code=code)
            save(output,'result-'+uuid.uuid4().hex+'.json',result)
        print(json.dumps(dict(status=result['status'],exit_code=code,error=result.get('error')),sort_keys=True),flush=True)
        return code
    finally:os.close(output_fd)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-host',action='store_true');parser.add_argument('--recipe',type=Path,required=True)
    parser.add_argument('--resume-output',type=Path)
    args=parser.parse_args(argv)
    if not args.prepare_host:parser.error('native post-boot preparation requires --prepare-host')
    return run(args.recipe,resume_output=args.resume_output)


if __name__=='__main__':raise SystemExit(main())
