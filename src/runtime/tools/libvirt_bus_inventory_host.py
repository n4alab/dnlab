"""One-shot bus prerequisite recipe; native execution needs explicit consent.

Only private reports are written. Current context is a fresh diagnostic, never
adoption of historical processes/resources. No library or bus is opened here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

RUNTIME=Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT=Path('/var/lib/dnlab-runtime-spikes')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def inventory():
    result={}
    for directory in ('tools','dnlab_runtime'):
        for path in (RUNTIME/directory).glob('*.py'):
            if path.is_symlink():raise ValueError('recipe source symlink refused')
            result[str(path.relative_to(RUNTIME))]=sha(path.read_bytes())
    if not result:raise ValueError('complete recipe source inventory required')
    return result


def validate(request):
    if (not isinstance(request,dict) or set(request)!={'nonce','host_id','scope'}
            or not isinstance(request['nonce'],str) or re.fullmatch('[0-9a-f]{32}',request['nonce']) is None
            or not isinstance(request['host_id'],str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',request['host_id']) is None
            or request['scope']!='bus-library-socket-readonly-v1'):
        raise ValueError('fixed bus inventory request required')


def prepare_recipe(folder,request):
    validate(request);folder=Path(folder);folder.mkdir(mode=0o700)
    raw=json.dumps(request,sort_keys=True).encode()
    (folder/'request.json').write_bytes(raw)
    receipt=dict(schema_version=1,runtime_root=str(RUNTIME),source_sha256=inventory(),request_sha256=sha(raw))
    (folder/'receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
    return receipt


def verify_recipe(folder):
    folder=Path(folder);raw=(folder/'request.json').read_bytes();request=json.loads(raw);validate(request)
    receipt=json.loads((folder/'receipt.json').read_text())
    if (receipt.get('schema_version')!=1 or receipt.get('runtime_root')!=str(RUNTIME)
            or receipt.get('source_sha256')!=inventory() or receipt.get('request_sha256')!=sha(raw)):
        raise ValueError('frozen bus inventory recipe differs')
    return request


def host_context(host_id):
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot) is None:raise ValueError('canonical boot ID required')
    namespaces={}
    for name in ('pid','mnt','net','user'):
        info=os.stat('/proc/self/ns/'+name);namespaces[name]=dict(device=info.st_dev,inode=info.st_ino)
    return dict(host_id=host_id,boot_id=boot,namespaces=namespaces)


def run(recipe,*,root_fd,read_context,output_parent):
    request=verify_recipe(recipe)
    from tools.libvirt_bus_prerequisites import collect
    parent=output=None;name='libvirt-bus-readonly-'+request['nonce'][:12]
    try:
        parent=os.open(output_parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        info=os.fstat(parent)
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('root-controlled report parent required')
        os.mkdir(name,mode=0o700,dir_fd=parent);os.fsync(parent)
        output=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        def persist(filename,raw):
            if not re.fullmatch('[A-Za-z0-9_.-]+',filename):raise ValueError('fixed private report name required')
            fd=os.open(filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=output)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(output)
        persist('intent.json',json.dumps(request,sort_keys=True).encode())
        try:
            expected=read_context()
            persist('initial-context.json',json.dumps(expected,sort_keys=True).encode())
            result=collect(root_fd,expected,context=read_context,persist=persist)
            if verify_recipe(recipe)!=request:raise ValueError('bus inventory recipe changed during collection')
        except Exception as error:
            result=dict(status='failed',qualified=False,error_type=type(error).__name__,error=str(error))
        persist('result.json',json.dumps(result,sort_keys=True).encode())
        return result,Path(output_parent)/name
    finally:
        if output is not None:os.close(output)
        if parent is not None:os.close(parent)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe',required=True,type=Path)
    parser.add_argument('--collect-host',action='store_true')
    args=parser.parse_args(argv)
    if not args.collect_host:parser.error('explicit --collect-host required')
    if not sys.dont_write_bytecode:parser.error('python -B required')
    request=verify_recipe(args.recipe)
    sys.path.insert(0,str(RUNTIME))
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:result,output=run(args.recipe,root_fd=root,read_context=lambda:host_context(request['host_id']),output_parent=OUTPUT_PARENT)
    finally:os.close(root)
    print(json.dumps(dict(result=result,output=str(output)),sort_keys=True))
    return 0 if result['status']=='collected' else 1


if __name__=='__main__':raise SystemExit(main())
