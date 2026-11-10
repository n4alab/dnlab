"""Explicit apply/recovery of one prepared current-session unit revision.

No new prepare, directory action, account command, reload/start or libvirt
connection is exposed. Recovery requires the original durable reference.
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
        'worker-profile.json','expected-context.json','postboot.json','prepared-reference.json','journal-binding.json',
        'effective-source.json','unit-window.json','unit-reference.json')


def verify_recipe(recipe):
    recipe=Path(recipe);receipt=json.loads((recipe/'receipt.json').read_text())
    sources={str(path.relative_to(RUNTIME)) for directory in ('dnlab_runtime','tools')
        for path in (RUNTIME/directory).glob('*.py')}
    if (receipt.get('schema_version')!=1 or receipt.get('runtime_root')!=str(RUNTIME)
            or set(receipt.get('input_sha256',{}))!=set(INPUTS) or not sources
            or set(receipt.get('source_sha256',{}))!=sources
            or receipt.get('entry_sha256')!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise RuntimeError('frozen current unit action recipe differs')
    for name,digest in receipt['source_sha256'].items():
        if hashlib.sha256((RUNTIME/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('unit action source changed: '+name)
    for name,digest in receipt['input_sha256'].items():
        if hashlib.sha256((recipe/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('unit action input changed: '+name)
    return receipt


def run(recipe,*,action,resume_output=None):
    if action not in ('apply','recover'):raise ValueError('explicit unit action required')
    recipe=Path(recipe);receipt=verify_recipe(recipe)
    inputs={name:json.loads((recipe/name).read_text()) for name in INPUTS}
    installed=inputs['installed.json'];original=inputs['journal-reference.json'];expected=inputs['expected-context.json']
    request=inputs['postboot.json'];binding=inputs['journal-binding.json'];agreement=inputs['unit-window.json']
    nonce=agreement['nonce']
    if (not isinstance(binding,dict) or not isinstance(nonce,str) or len(nonce)!=32
            or any(c not in '0123456789abcdef' for c in nonce)):
        raise RuntimeError('original current unit action inputs required')
    sys.path.insert(0,str(RUNTIME))
    from dnlab_runtime.libvirt_account_identity import host_query
    from dnlab_runtime.libvirt_account_runner import open_resource
    from dnlab_runtime.libvirt_account_worker import binary_proof
    from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
    from tools.libvirt_configuration_prepare import context,save
    from tools.libvirt_postboot_directories import PostBootDirectoryAssembly
    from tools.libvirt_postboot_journal import open_postboot_journal
    from tools.libvirt_postboot_prepare_host import read_output
    from tools.libvirt_postboot_unit_revision import PostBootUnitRevision
    output=OUTPUT_PARENT/('libvirt-current-unit-'+action+'-'+nonce[:12])
    if resume_output is not None and Path(resume_output)!=output:raise RuntimeError('original unit action output required')
    parent=os.open(OUTPUT_PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(parent)
        if info.st_uid!=os.getuid() or info.st_mode&0o022:raise RuntimeError('private unit action output parent differs')
        if resume_output is None:os.mkdir(output.name,mode=0o700,dir_fd=parent);os.fsync(parent)
        fd=os.open(output.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    try:
        info=os.fstat(fd)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('private unit action output differs')
        intent=dict(kind='native-current-unit-action-v1',action=action,window=agreement,recipe=receipt,
            unit_reference=inputs['unit-reference.json'],
            journal_binding=binding,effective_source=inputs['effective-source.json'])
        if resume_output is None:save(output,'invocation.json',intent)
        elif read_output(fd,'invocation.json')!=intent:raise RuntimeError('original unit action invocation differs')
        print('Output: '+str(output),flush=True)
        result=dict(status='requested',scope='unit-policy-revision-only',daemon_ready=False,
            started=time.time(),contexts=[]);queries=[];directories=None;code=1
        try:
            def verify():
                current=context(installed);result['contexts'].append(dict(expected=expected,observed=current))
                if current!=expected:raise RuntimeError('explicit current unit action context differs')
                visible=os.stat(output,follow_symlinks=False)
                if (visible.st_dev,visible.st_ino)!=(info.st_dev,info.st_ino):raise RuntimeError('original unit action output replaced')
                verify_recipe(recipe)
            verify()
            with ExitStack() as stack:
                executable=stack.enter_context(open_resource('/usr/bin/systemctl'))
                binary_proof(executable,receipt['systemctl_sha256'])
                names=installed['profile']['service_order']+installed['profile']['forbidden_vendor_activation']
                allowed=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',*names]
                def query(argv,*,env,timeout):
                    if argv!=allowed or timeout!=5:raise RuntimeError('readonly unit action query differs')
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
                def no_new_binding(value):raise RuntimeError('unit action cannot retain a new journal binding')
                journal,_=stack.enter_context(open_postboot_journal(original['directory'],installed,
                    identity=original['identity'],initial_sha256=original['database_sha256'],
                    retain=no_new_binding,verify=verify,original_binding=binding))
                closed=ProvisioningWindow(request['window'],lambda:None)
                directories=PostBootDirectoryAssembly(journal,installed,expected,
                    prepared_reference=inputs['prepared-reference.json'],qualification_id=request['qualification_id'],
                    recovery_id=request['recovery_id'],run_parent=request['run_parent'],window=closed,
                    expected_packages=inputs['expected-packages.json'],approved_account_inputs=inputs['approved-account-inputs.json'],
                    worker_profile=inputs['worker-profile.json'],query=query,nss_query=host_query)
                window=ProvisioningWindow(agreement,lambda:json.loads((recipe/'unit-window.json').read_text()))
                unit=PostBootUnitRevision(directories,effective_source=inputs['effective-source.json'],
                    window=window,unit_reference=inputs['unit-reference.json'])
                if action=='apply':unit.apply_original()
                else:unit.recover_original()
                effective=unit.effective()
                if effective['configuration_revision']['operation_id']!=inputs['unit-reference.json']['id']:
                    raise RuntimeError('original effective unit revision differs')
                artifact=dict(scope='unit-policy-revision-only',daemon_ready=False,source=effective)
                previous=read_output(fd,'effective.json')
                if previous is None:save(output,'effective.json',artifact)
                elif previous!=artifact:raise RuntimeError('original effective unit output differs')
                verify();binary_proof(executable,receipt['systemctl_sha256'])
                result.update(status='unit_qualified',revision_id=inputs['unit-reference.json']['id']);code=0
        except BaseException as error:
            result.update(status='failed',error=dict(type=type(error).__name__,message=str(error)),traceback=traceback.format_exc())
        finally:
            if directories is not None:result['diagnostics']=directories.diagnostics
            result.update(queries=queries,finished=time.time(),exit_code=code)
            save(output,'result-'+uuid.uuid4().hex+'.json',result)
        print(json.dumps(dict(status=result['status'],exit_code=code,error=result.get('error')),sort_keys=True),flush=True)
        return code
    finally:os.close(fd)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    flags=parser.add_mutually_exclusive_group(required=True)
    flags.add_argument('--apply-host',action='store_true');flags.add_argument('--recover-host',action='store_true')
    parser.add_argument('--recipe',type=Path,required=True)
    parser.add_argument('--resume-output',type=Path);args=parser.parse_args(argv)
    return run(args.recipe,action='apply' if args.apply_host else 'recover',resume_output=args.resume_output)


if __name__=='__main__':raise SystemExit(main())
