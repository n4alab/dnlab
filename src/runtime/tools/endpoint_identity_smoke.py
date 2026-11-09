#!/usr/bin/env python3
"""Index-bound endpoint cleanup in an owned private namespace; no VD images."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Backend,Linux
from dnlab_runtime.kernel_endpoint import signature
from dnlab_runtime.manifest import Conflict


def run():
    root=Path(tempfile.mkdtemp(prefix='dnlab-endpoint-identity-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8];name='drsp-endpoint-'+token;fd=None
    report={'status':'running','scope':'owned private netns; real kernel veth and netlink deletion'}
    def command(args):return subprocess.run(args,capture_output=True,text=True,timeout=30,check=True).stdout
    try:
        command(['ip','netns','add',name]);fd=os.open('/run/netns/'+name,os.O_RDONLY)
        ns_info=os.fstat(fd)
        class ScopedLinux(Linux):
            hook=None
            def network_identity(self):
                return {**super().network_identity(),'device':ns_info.st_dev,'inode':ns_info.st_ino}
            def run(self,args,*,pass_fds=()):
                return super().run(['nsenter',f'--net=/proc/self/fd/{fd}','--',*args],pass_fds=tuple(set((*pass_fds,fd))))
            def delete_link(self,expected):
                if self.hook is not None:
                    hook=self.hook;self.hook=None;hook(expected)
                return super().delete_link(expected)
        linux=ScopedLinux();backend=Backend(linux=linux)
        request={'lab_id':'drsp-'+token,'node_id':'a'}
        spec={'endpoints':[{'host_interface':'owned0','node_interface':'eth1'}]}
        def create(alias):
            linux.command(['link','add','owned0','address','02:da:00:00:00:01','type','veth','peer','name','peer0','address','02:da:00:00:00:02'])
            linux.command(['link','set','owned0','alias',alias]);return linux.link('owned0')
        # Ordinary indexed delete and verified namespace transport.
        create(backend.alias(request,spec));backend.delete_endpoints(request,spec)
        assert linux.link('owned0') is None and linux.link('peer0') is None
        report['ordinary_delete']=True
        create(backend.alias(request,spec))
        def replace(expected):
            Linux.delete_link(linux,expected)
            report['foreign_identity']=signature(create('fixture-foreign:'+token))
            assert report['foreign_identity']['ifindex']!=expected['ifindex']
        linux.hook=replace
        try:backend.delete_endpoints(request,spec)
        except Conflict:pass
        else:raise RuntimeError('replacement accepted as cleaned')
        assert signature(linux.link('owned0'))==report['foreign_identity']
        try:backend.delete_endpoints(request,spec)
        except Conflict:pass
        else:raise RuntimeError('foreign retry accepted')
        assert signature(linux.link('owned0'))==report['foreign_identity']
        report['foreign_replacement_and_retry_preserved']=True
        Linux.delete_link(linux,linux.link('owned0'))  # Fixture owns the private test resource.
        create(backend.alias(request,spec))
        linux.hook=lambda expected:Linux.delete_link(linux,expected)
        backend.delete_endpoints(request,spec);assert linux.link('owned0') is None
        report['disappearance_before_delete']=True
        original=create(backend.alias(request,spec))
        bad=linux.network_identity();bad['inode']+=1
        identity=linux.network_identity;linux.network_identity=lambda:bad
        try:linux.delete_link(original)
        except Conflict:pass
        else:raise RuntimeError('wrong namespace accepted')
        linux.network_identity=identity
        assert signature(linux.link('owned0'))==signature(original)
        report['namespace_mismatch_refused']=True
        backend.delete_endpoints(request,spec)
        report['status']='passed'
    except Exception as error:report['status']='failed';report['error']=str(error);raise
    finally:
        try:
            if fd is not None:
                current=os.stat('/run/netns/'+name)
                assert (current.st_dev,current.st_ino)==(ns_info.st_dev,ns_info.st_ino)
                os.close(fd);fd=None;command(['ip','netns','delete',name])
            report['cleanup_verified']=not Path('/run/netns/'+name).exists()
        except Exception as error:report['cleanup_verified']=False;report['cleanup_error']=str(error)
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified')}))
    assert report['cleanup_verified']


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    if not args.execute:parser.error('explicit --execute required')
    run()
