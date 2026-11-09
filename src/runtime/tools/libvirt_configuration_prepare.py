"""Explicit native prepare only; never stage a file or activate a service.

A frozen private recipe supplies the original installed record, snapshot and
journal reference. Importing this module does not read those inputs or the host.
"""
import argparse
from contextlib import ExitStack,closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time
import traceback

INPUTS=('request.json','baseline.json','installation-window.json','expected-packages.json',
        'approved-account-inputs.json','worker-profile.json','installed.json',
        'journal-reference.json','revision-window.json')
RUNTIME=Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT=Path('/var/lib/dnlab-runtime-spikes')


def verify_recipe(recipe):
    recipe=Path(recipe)
    receipt=json.loads((recipe/'receipt.json').read_text())
    sources={str(path.relative_to(RUNTIME)) for directory in ('dnlab_runtime','tools')
        for path in (RUNTIME/directory).glob('*.py')}
    if (receipt.get('schema_version')!=1 or receipt.get('runtime_root')!=str(RUNTIME)
            or set(receipt.get('input_sha256',{}))!=set(INPUTS)
            or receipt.get('entry_sha256')!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or not sources or set(receipt.get('source_sha256',{}))!=sources):
        raise RuntimeError('frozen configuration recipe differs')
    for name,sha in receipt['source_sha256'].items():
        path=Path(name)
        if path.is_absolute() or '..' in path.parts or path.suffix!='.py' or path.parts[0] not in ('dnlab_runtime','tools'):
            raise RuntimeError('unexpected recipe source path')
        if hashlib.sha256((RUNTIME/path).read_bytes()).hexdigest()!=sha:
            raise RuntimeError('prepared runtime source changed: '+name)
    for name,sha in receipt['input_sha256'].items():
        if hashlib.sha256((recipe/name).read_bytes()).hexdigest()!=sha:
            raise RuntimeError('original recipe input changed: '+name)
    return receipt


def context(installed):
    namespaces={}
    for name in ('pid','mnt','net','user'):
        info=os.stat('/proc/self/ns/'+name)
        namespaces[name]=dict(device=info.st_dev,inode=info.st_ino)
    return dict(host_id=installed['context']['host_id'],
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),namespaces=namespaces)


def save(output,name,value):
    fd=os.open(output/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
        stream.flush();os.fsync(stream.fileno())
    parent=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)


def original_journal(reference,installed,pinned_file,fingerprint):
    path=Path(reference['directory'])/'journal.sqlite3'
    if os.path.lexists(str(path)+'-wal'):raise RuntimeError('original journal WAL is active or uncertain')
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        with pinned_file(root,str(path).lstrip('/')) as (fd,info):
            if info.st_uid!=0 or info.st_mode&0o022 or info.st_size>16*1024*1024:
                raise RuntimeError('original journal metadata differs')
            digest=hashlib.sha256();remaining=info.st_size
            while remaining:
                block=os.read(fd,min(65536,remaining))
                if not block:raise RuntimeError('original journal truncated')
                digest.update(block);remaining-=len(block)
            if os.read(fd,1) or digest.hexdigest()!=reference['database_sha256']:
                raise RuntimeError('original installed journal hash differs')
    finally:os.close(root)
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
        if db.execute('SELECT identity FROM journal_identity').fetchone()[0]!=reference['identity']:
            raise RuntimeError('original journal identity differs')
        row=db.execute('SELECT payload,fingerprint FROM libvirt_install_intents WHERE id=?',(installed['id'],)).fetchone()
        if row is None or json.loads(row[0])!=installed or row[1]!=fingerprint(installed):
            raise RuntimeError('original installed intent differs')


def run(recipe):
    recipe=Path(recipe);receipt=verify_recipe(recipe)
    inputs={name:json.loads((recipe/name).read_text()) for name in INPUTS}
    installed=inputs['installed.json'];reference=inputs['journal-reference.json']
    window_receipt=inputs['revision-window.json']
    parent=OUTPUT_PARENT
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise RuntimeError('private output parent differs')
        name='libvirt-configuration-prepare-'+window_receipt['nonce'][:12]
        os.mkdir(name,mode=0o700,dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)
    output=parent/name
    print('Output: '+str(output),flush=True)
    save(output,'intent.json',dict(prepare_only=True,installed_id=installed['id'],
        window=window_receipt,journal_reference=reference,recipe=receipt))
    sys.path.insert(0,str(RUNTIME))
    from dnlab_runtime.journal import Journal
    from dnlab_runtime.libvirt_account_identity import host_query
    from dnlab_runtime.libvirt_account_runner import open_resource,source_proof,AccountProcessRunner
    from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
    from dnlab_runtime.libvirt_account_worker import binary_proof
    from dnlab_runtime.libvirt_configuration_session import ConfigurationSession
    from dnlab_runtime.libvirt_install_session import SessionProvisioning
    from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
    from dnlab_runtime.libvirt_service_profile import render_profile
    from dnlab_runtime.manifest import fingerprint
    from dnlab_runtime.vm_bundle import pinned_file
    from tools.libvirt_install_activity import InstallationActivity
    from tools.libvirt_install_snapshot import InstallationSnapshot

    class CommittedRunner(AccountProcessRunner):
        def arm(self,*args,**kwargs):raise RuntimeError('prepare cannot arm an account worker')
        def release(self,*args,**kwargs):raise RuntimeError('prepare cannot release an account worker')
        def outcome(self,*args,**kwargs):raise RuntimeError('prepare can only read committed account outcomes')

    result=dict(status='prepare_requested',qualified=False,started=time.time())
    journal=None;process_observer=None;activity=None;queries=[];code=1
    try:
        result['context_before']=context(installed)
        if result['context_before']!=installed['context']:raise RuntimeError('original installation context differs')
        original_journal(reference,installed,pinned_file,fingerprint)
        request=inputs['request.json'];worker=inputs['worker-profile.json']
        with ExitStack() as stack:
            systemctl=stack.enter_context(open_resource('/usr/bin/systemctl'))
            binary_proof(systemctl,receipt['systemctl_sha256'])
            python=stack.enter_context(open_resource(worker['python']['path']))
            source=stack.enter_context(open_resource(worker['worker']['path']))
            binary_proof(python,worker['python']['sha256']);source_proof(source,worker['worker']['sha256'])
            profile=render_profile(**request)
            expected=['/usr/bin/systemctl','show','--all','--no-pager','--property=Id,LoadState,ActiveState,Job','--',
                *profile['service_order'],*profile['forbidden_vendor_activation']]
            def query(argv,*,env,timeout):
                if argv!=expected or timeout!=5:raise RuntimeError('readonly query differs')
                binary_proof(systemctl,receipt['systemctl_sha256'])
                entry=dict(argv=argv,timeout=timeout,status='requested');queries.append(entry)
                try:
                    completed=subprocess.run(argv,executable='/proc/self/fd/'+str(systemctl),pass_fds=(systemctl,),
                        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        env=env,cwd='/',timeout=timeout,check=False)
                except BaseException as error:
                    entry.update(status='failed',error=dict(type=type(error).__name__,message=str(error)));raise
                entry.update(status='completed',exit_code=completed.returncode,
                    stdout=completed.stdout.decode('utf-8','replace'),stderr=completed.stderr.decode('utf-8','replace'))
                return {key:entry[key] for key in ('exit_code','stdout','stderr')}
            activity=InstallationActivity(profile,query=query)
            provider=InstallationSnapshot('/',request,inputs['expected-packages.json'],inputs['approved-account-inputs.json'],
                namespaces=activity.namespaces,services=activity)
            historical=ProvisioningWindow(inputs['installation-window.json'],lambda:None)
            window=ProvisioningWindow(window_receipt,lambda:json.loads((recipe/'revision-window.json').read_text()))
            journal=Journal(Path(reference['directory']))
            if journal.identity!=reference['identity']:raise RuntimeError('original journal changed before assembly')
            process_observer=AccountWorkerObserver(journal)
            runner=CommittedRunner(journal,profile=worker,observer=process_observer)
            provisioning=SessionProvisioning(journal,root='/',request=request,snapshot_provider=provider,
                original_snapshot=inputs['baseline.json']['snapshot'],window=historical,runner=runner,
                nss_query=host_query,directory_receipts=installed['dependencies'])
            revision=ConfigurationSession(provisioning,installed,window=window,journal_identity=reference['identity'])
            prepared=revision.prepare()
            save(output,'prepared-reference.json',prepared)
            result['original_record_unchanged']=provisioning.installer.read(installed['id'])==installed
            if not result['original_record_unchanged']:raise RuntimeError('original installation record changed')
            result['context_after']=context(installed)
            if result['context_after']!=result['context_before']:raise RuntimeError('context changed during prepare')
            binary_proof(systemctl,receipt['systemctl_sha256'])
            verify_recipe(recipe)
            result.update(status='prepared',operation_id=prepared['id'],phase=prepared['phase']);code=0
    except BaseException as error:
        result.update(status='failed',error=dict(type=type(error).__name__,message=str(error)),traceback=traceback.format_exc())
    finally:
        cleanup=[]
        for step,resource in (('observer_close',process_observer),('journal_close',journal)):
            if resource is None:continue
            try:resource.close()
            except BaseException as error:
                cleanup.append(dict(step=step,type=type(error).__name__,message=str(error)))
        if cleanup:
            result['status']='failed';code=1
            result.setdefault('error',dict(type='CleanupError',message='prepare resource closure failed'))
        result['cleanup_errors']=cleanup
        if activity is not None:result['activity_diagnostics']=activity.diagnostics
        result.update(queries=queries,finished=time.time(),exit_code=code)
        save(output,'result.json',result)
        print(json.dumps(dict(status=result['status'],exit_code=code,error=result.get('error')),sort_keys=True),flush=True)
    return code


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-host',action='store_true')
    parser.add_argument('--recipe',type=Path,required=True)
    args=parser.parse_args(argv)
    if not args.prepare_host:parser.error('native preparation requires --prepare-host')
    return run(args.recipe)


if __name__=='__main__':raise SystemExit(main())
