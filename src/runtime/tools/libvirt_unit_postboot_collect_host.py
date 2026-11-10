"""Readonly new-boot observation retaining the original prepared unit reference.

A frozen private recipe identifies the original journal and expected current
context. All imports of runtime observers follow source validation in run().
"""
import argparse
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

RUNTIME=Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT=Path('/var/lib/dnlab-runtime-spikes')
INPUTS=('installed.json','journal-reference.json','expected-packages.json','approved-account-inputs.json',
        'worker-profile.json','expected-context.json','collection.json','journal-binding.json',
        'unit-reference.json','effective-source.json','prepared-reference.json')


def verify_recipe(recipe):
    recipe=Path(recipe);receipt=json.loads((recipe/'receipt.json').read_text())
    sources={str(path.relative_to(RUNTIME)) for directory in ('dnlab_runtime','tools') for path in (RUNTIME/directory).glob('*.py')}
    if (receipt.get('schema_version')!=1 or receipt.get('runtime_root')!=str(RUNTIME)
            or set(receipt.get('input_sha256',{}))!=set(INPUTS) or not sources
            or set(receipt.get('source_sha256',{}))!=sources
            or receipt.get('entry_sha256')!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise RuntimeError('frozen readonly collection recipe differs')
    for name,sha in receipt['source_sha256'].items():
        if hashlib.sha256((RUNTIME/name).read_bytes()).hexdigest()!=sha:raise RuntimeError('collection source changed: '+name)
    for name,sha in receipt['input_sha256'].items():
        if hashlib.sha256((recipe/name).read_bytes()).hexdigest()!=sha:raise RuntimeError('collection input changed: '+name)
    return receipt


def run(recipe):
    recipe=Path(recipe);receipt=verify_recipe(recipe)
    inputs={name:json.loads((recipe/name).read_text()) for name in INPUTS}
    collection=inputs['collection.json'];nonce=collection['nonce']
    if not isinstance(nonce,str) or len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):
        raise RuntimeError('explicit collection nonce required')
    installed=inputs['installed.json'];reference=inputs['journal-reference.json'];expected=inputs['expected-context.json']
    sys.path.insert(0,str(RUNTIME))
    from dnlab_runtime.libvirt_account_history import HistoricalAccountCreation
    from dnlab_runtime.libvirt_account_identity import LocalAccountIdentity,host_query
    from dnlab_runtime.libvirt_account_runner import open_resource
    from dnlab_runtime.libvirt_account_worker import binary_proof
    from dnlab_runtime.libvirt_install import SessionInstaller
    from dnlab_runtime.libvirt_install_files import InstallationFiles
    from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
    from dnlab_runtime.libvirt_postboot import context as validate_context,plan
    from dnlab_runtime.manifest import identifier
    from tools.libvirt_configuration_prepare import context,save
    from tools.libvirt_postboot_readonly_journal import readonly_bound_journal
    from tools.libvirt_postboot_collect import PostBootCollection
    from tools.libvirt_unit_postboot_collection import UnitPostBootCollection
    from tools.libvirt_install_snapshot import InstallationSnapshot
    from tools.libvirt_install_activity import InstallationActivity
    identifier(collection['id'],'collection operation_id');validate_context(expected);plan(installed,expected)
    parent=OUTPUT_PARENT;fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('private readonly output parent differs')
        name='libvirt-unit-postboot-readonly-'+nonce[:12];os.mkdir(name,mode=0o700,dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)
    output=parent/name;print('Output: '+str(output),flush=True)
    save(output,'intent.json',dict(readonly=True,collection=collection,expected_context=expected,journal_reference=reference,recipe=receipt))
    result=dict(status='collection_requested',qualified=False,started=time.time(),contexts=[]);code=1
    reader=None;activity=None;queries=[];cleanup=[]
    try:
        result['context_before']=context(installed)
        if result['context_before']!=expected:raise RuntimeError('explicit current collection context differs')
        with ExitStack() as stack:
            def verify():
                observed=context(installed)
                result['contexts'].append(dict(expected=expected,observed=observed))
                if observed!=expected:raise RuntimeError('unit post-boot collection context changed')
                verify_recipe(recipe)
            journal,journal_receipt=stack.enter_context(readonly_bound_journal(reference['directory'],installed,
                binding=inputs['journal-binding.json'],verify=verify))
            source=SessionInstaller(journal,None,readonly=True)
            files=InstallationFiles('/',journal=journal,readonly=True)
            identity=LocalAccountIdentity('/',nss_query=host_query)
            dependencies=[item['spec'] for item in installed['items'] if item['phase']=='dependency']
            dependency=InstallationDirectoryDependencies('/',dependencies) if dependencies else None
            def directory(spec):
                if dependency is None:raise RuntimeError('no dependency selected')
                return dependency(spec)
            binaries={role:dict(path='/usr/sbin/'+role,sha256=installed['prerequisites']['account_inputs']['usr/sbin/'+role]['sha256'])
                for role in ('groupadd','useradd')}
            history=HistoricalAccountCreation(journal,installation=installed,worker_profile=inputs['worker-profile.json'],
                binaries=binaries,source_reader=source.read)
            executable=stack.enter_context(open_resource('/usr/bin/systemctl'));binary_proof(executable,receipt['systemctl_sha256'])
            profile=installed['profile']
            argv_expected=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',
                *profile['service_order'],*profile['forbidden_vendor_activation']]
            def query(argv,*,env,timeout):
                if argv!=argv_expected or timeout!=5:raise RuntimeError('readonly collection query differs')
                binary_proof(executable,receipt['systemctl_sha256']);entry=dict(argv=argv,status='requested');queries.append(entry)
                try:
                    completed=subprocess.run(argv,executable='/proc/self/fd/'+str(executable),pass_fds=(executable,),
                        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd='/',timeout=timeout,check=False)
                except BaseException as error:
                    entry.update(status='failed',error=dict(type=type(error).__name__,message=str(error)));raise
                entry.update(status='completed',exit_code=completed.returncode,
                    stdout=completed.stdout.decode('utf-8','replace'),stderr=completed.stderr.decode('utf-8','replace'))
                return {key:entry[key] for key in ('exit_code','stdout','stderr')}
            activity=InstallationActivity(profile,query=query)
            snapshot=InstallationSnapshot('/',installed['request'],inputs['expected-packages.json'],inputs['approved-account-inputs.json'],
                namespaces=activity.namespaces,services=activity)
            reader=PostBootCollection(installed,expected,source_reader=source.read,snapshot=snapshot,identity=identity,
                files=files,directory_dependency=directory,history=history)
            historical=UnitPostBootCollection(reader,journal,reference=inputs['unit-reference.json'],
                effective_source=inputs['effective-source.json'],directory_reference=inputs['prepared-reference.json'])
            observed=historical.collect();observed['journal']=journal_receipt;save(output,'observation.json',observed)
            binary_proof(executable,receipt['systemctl_sha256'])
        result['context_after']=context(installed)
        if result['context_after']!=expected:raise RuntimeError('collection context changed')
        verify_recipe(recipe)
        result.update(status='collected',pending_volatile=observed['pending_volatile'],prerequisite_differences=observed['prerequisite_differences']);code=0
    except BaseException as error:
        result.update(status='failed',error=dict(type=type(error).__name__,message=str(error)),traceback=traceback.format_exc())
    finally:
        if reader is not None:result['diagnostics']=reader.diagnostics
        if activity is not None:result['activity_diagnostics']=activity.diagnostics
        result.update(queries=queries,cleanup_errors=cleanup,finished=time.time(),exit_code=code)
        save(output,'result.json',result)
        print(json.dumps(dict(status=result['status'],exit_code=code,error=result.get('error')),sort_keys=True),flush=True)
    return code


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--collect-host',action='store_true')
    parser.add_argument('--recipe',type=Path,required=True);args=parser.parse_args(argv)
    if not args.collect_host:parser.error('native readonly collection requires --collect-host')
    return run(args.recipe)


if __name__=='__main__':raise SystemExit(main())
