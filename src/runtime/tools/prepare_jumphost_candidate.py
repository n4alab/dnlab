#!/usr/bin/env python3
"""Build/audit the jumphost fixture candidate without running a container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import subprocess
import tarfile
import tempfile
import sys
from urllib.parse import quote

ROOT=Path(__file__).resolve().parents[3]
RECIPE=Path(__file__).with_name('jumphost_candidate.Dockerfile')
CONTEXT=ROOT/'src/multinode/jumphost'
ASSETS={'entrypoint.sh':'/entrypoint.sh','inventory.py':'/usr/local/lib/dnlab-inventory.py',
        'vd':'/usr/local/bin/vd','vd-relay-client':'/usr/local/bin/vd-relay-client'}
sys.path.insert(0,str(ROOT/'src/runtime'))
from dnlab_runtime.backend import Docker


def inspect_image(image):
    result=subprocess.run(['docker','image','inspect',image],capture_output=True,text=True,timeout=30,check=True)
    rows=json.loads(result.stdout)
    if len(rows)!=1:raise RuntimeError('image inspection ambiguous')
    return rows[0]


def root_path(value):
    if '..' in value.split('/'):raise RuntimeError('image archive path contains traversal')
    return '/'+posixpath.normpath(value.lstrip('/')).lstrip('./')


def apply_layer(nodes,layer):
    members=layer.getmembers()
    # OCI whiteouts remove lower-layer entries before this layer's entries.
    for member in members:
        path=root_path(member.name);name=posixpath.basename(path);parent=posixpath.dirname(path)
        if name=='.wh..wh..opq':
            for old in list(nodes):
                if old.startswith(parent+'/'):del nodes[old]
        elif name.startswith('.wh.'):
            target=posixpath.join(parent,name[4:])
            for old in list(nodes):
                if old==target or old.startswith(target+'/'):del nodes[old]
    for member in members:
        path=root_path(member.name)
        if posixpath.basename(path).startswith('.wh.'):continue
        kind='file' if member.isfile() else 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'directory' if member.isdir() else 'other'
        row={'kind':kind,'mode':member.mode,'uid':member.uid,'gid':member.gid,'link':member.linkname}
        if member.isfile():
            with layer.extractfile(member) as stream:
                row['prefix']=stream.read(128)
                if path in ASSETS.values():
                    sha=hashlib.sha256();sha.update(row['prefix'])
                    while chunk:=stream.read(65536):sha.update(chunk)
                    row['sha256']=sha.hexdigest()
        nodes[path]=row


def resolve_node(nodes,path):
    for _ in range(32):
        parts=path.strip('/').split('/');changed=False
        for index in range(len(parts)):
            prefix='/'+('/'.join(parts[:index+1]));node=nodes.get(prefix)
            if node and node['kind']=='symlink':
                target=node['link'] if node['link'].startswith('/') else posixpath.join(posixpath.dirname(prefix),node['link'])
                path=posixpath.normpath(posixpath.join(target,*parts[index+1:]));changed=True;break
        if changed:continue
        node=nodes.get(path)
        if node and node['kind']=='hardlink':path=root_path(node['link']);continue
        return path,node
    raise RuntimeError('image interpreter link cycle')


def audit_nodes(nodes,expected):
    entry=nodes.get('/entrypoint.sh')
    if (not entry or entry['kind']!='file' or entry['mode']!=0o755 or entry['uid']!=0 or entry['gid']!=0
            or entry.get('sha256')!=expected['entrypoint.sh']):
        raise RuntimeError('candidate entrypoint mode, ownership or source differs; expected root:root 0755')
    if entry['prefix'].split(b'\n',1)[0]!=b'#!/bin/bash':raise RuntimeError('candidate entrypoint interpreter differs')
    resolved,interpreter=resolve_node(nodes,'/bin/bash')
    if (not interpreter or interpreter['kind']!='file' or not interpreter['mode']&0o111
            or interpreter['mode']&0o022 or interpreter['uid']!=0 or interpreter['gid']!=0
            or interpreter.get('prefix',b'')[:4]!=b'\x7fELF'):
        raise RuntimeError('candidate bash interpreter absent, non-executable or unqualified')
    inventory=nodes.get('/usr/local/lib/dnlab-inventory.py')
    if (not inventory or inventory['kind']!='file' or inventory['mode']!=0o644 or inventory['uid']!=0 or inventory['gid']!=0
            or inventory.get('sha256')!=expected['inventory.py']):
        raise RuntimeError('candidate inventory mode, ownership or source differs')
    for name,shebang in (('vd',b'#!/bin/bash'),('vd-relay-client',b'#!/usr/bin/env python3')):
        node=nodes.get(ASSETS[name])
        if (not node or node['kind']!='file' or node['mode']!=0o755 or node['uid']!=0 or node['gid']!=0
                or node.get('sha256')!=expected[name] or node.get('prefix',b'').split(b'\n',1)[0]!=shebang):
            raise RuntimeError('candidate '+name+' mode, ownership, interpreter or source differs')
    interpreters={}
    for path in ('/usr/bin/env','/usr/bin/python3'):
        target,node=resolve_node(nodes,path)
        if (not node or node['kind']!='file' or not node['mode']&0o111 or node['mode']&0o022
                or node['uid']!=0 or node['gid']!=0 or node.get('prefix',b'')[:4]!=b'\x7fELF'):
            raise RuntimeError('candidate CLI interpreter absent, non-executable or unqualified')
        interpreters[path]=target
    return {'status':'passed','entrypoint_mode':'0755','entrypoint_interpreter':'/bin/bash','interpreter_resolved_path':resolved,
            'interpreter_mode':format(interpreter['mode'],'04o'),'interpreter_elf':True,'inventory_mode':'0644',
            'cli_modes':{'vd':'0755','vd-relay-client':'0755'},'cli_interpreters':interpreters,'source_sha256':expected}


def audit_image(image,output):
    output=Path(output);proof=inspect_image(image)
    if proof['Id']!=image or proof['Config'].get('Entrypoint')!=['/entrypoint.sh']:
        raise RuntimeError('immutable candidate ID and entrypoint required')
    caps=(proof['Config'].get('Labels') or {}).get('io.dnlab.jumphost.capabilities','').split(',')
    if 'qualified-relay-inventory-v1' not in caps:raise RuntimeError('candidate qualified inventory capability missing')
    expected={name:hashlib.sha256((CONTEXT/name).read_bytes()).hexdigest() for name in ASSETS}
    fd,temporary=tempfile.mkstemp(dir=output,prefix='image-audit-',suffix='.tar')
    try:
        with os.fdopen(fd,'wb') as stream:
            subprocess.run(['docker','image','save',image],stdout=stream,stderr=subprocess.PIPE,timeout=90,check=True)
        nodes={}
        with tarfile.open(temporary) as archive:
            manifests=json.load(archive.extractfile('manifest.json'))
            if len(manifests)!=1:raise RuntimeError('image archive manifest ambiguous')
            for layer in manifests[0]['Layers']:
                with tarfile.open(fileobj=archive.extractfile(layer)) as contents:apply_layer(nodes,contents)
        report=dict(audit_nodes(nodes,expected),image=image,container_created=False)
        (output/'candidate-audit.json').write_text(json.dumps(report,indent=2)+'\n')
        return report
    except Exception as error:
        (output/'candidate-audit.json').write_text(json.dumps({'status':'failed','image':image,'error_type':type(error).__name__,'error':str(error)},indent=2)+'\n')
        raise
    finally:os.unlink(temporary)


def build(base,expected_base,tag,output):
    output=Path(output);output.mkdir(mode=0o700,parents=True,exist_ok=False)
    before=inspect_image(base)
    if before['Id']!=expected_base:raise RuntimeError('local base ID differs; no build')
    existing=Docker().request('GET','/images/'+quote(tag,safe='')+'/json',missing_ok=True)
    if existing is not None:raise RuntimeError('candidate tag already exists; refusing replacement')
    with (output/'build.log').open('w') as log:
        subprocess.run(['docker','build','--pull=false','--network=none','--build-arg','BASE_IMAGE='+base,
            '--label','org.dnlab.fixture=management-services-candidate','-f',str(RECIPE),'-t',tag,
            '--iidfile',str(output/'image-id'),str(CONTEXT)],stdout=log,stderr=subprocess.STDOUT,timeout=180,check=True)
    candidate=inspect_image(tag)
    if (inspect_image(base)['Id']!=expected_base
            or candidate['RootFS']['Layers'][:len(before['RootFS']['Layers'])]!=before['RootFS']['Layers']):
        raise RuntimeError('candidate base layers differ from original pinned base')
    report=audit_image(candidate['Id'],output)
    report.update(base_image=expected_base,candidate_tag=tag,recipe_sha256=hashlib.sha256(RECIPE.read_bytes()).hexdigest())
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base-image',required=True);parser.add_argument('--expected-base-id',required=True)
    parser.add_argument('--tag',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    build(args.base_image,args.expected_base_id,args.tag,args.output)
