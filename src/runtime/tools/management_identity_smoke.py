#!/usr/bin/env python3
"""Isolated kernel gate for management infrastructure ownership and recovery.

Run ONLY through `unshare --net -- <python> this-file --output /tmp/...`.
All network resources/firewall rules are created in that disposable namespace.
No Docker, plugin installation, host route or production lab is changed.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import shlex
from types import SimpleNamespace
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'multinode'))
from dnlab_multinode.services.management_host import Worker, ManagementError, context, execute, signature


def stable_snapshot(snapshot):
    value=copy.deepcopy(snapshot)
    for resource in value['resources'].values():
        config=resource['config']
        if config.get('info_kind')=='bridge':config.get('info_data',{}).pop('gc_timer',None)
        if config.get('info_kind')=='vxlan':config.get('info_slave_data',{}).pop('forward_delay_timer',None)
    return value


def routing_gate(worker, root, save):
    """Real packets through two disposable guest namespaces and a router guest."""
    children=[];ports=[];receipts={};context_before=context()
    def run(args, *, fds=(), check=True):
        result=subprocess.run(args,text=True,capture_output=True,timeout=15,pass_fds=fds)
        if check and result.returncode:raise RuntimeError(f'route fixture rc={result.returncode}: {args}: {result.stderr}')
        return result
    def child(name):
        proc=subprocess.Popen(['unshare','--net','--',sys.executable,'-u','-c',
            "import json,os,sys;print(json.dumps({'pid':os.getpid(),'inode':os.stat('/proc/self/ns/net').st_ino}),flush=True);sys.stdin.read()"],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append([name,proc,None]);value=json.loads(proc.stdout.readline());fd=os.open(f'/proc/{proc.pid}/ns/net',os.O_RDONLY)
        children[-1][2]=fd
        if value['pid']!=proc.pid or os.fstat(fd).st_ino!=value['inode']:raise RuntimeError('route namespace identity differs')
        save('routing-intent.json',dict(context=context_before,children=[dict(name=n,pid=p.pid,inode=os.fstat(f).st_ino) for n,p,f in children],ports=ports))
        return fd
    def ns(fd,args,check=True):return run(['nsenter','--net=/proc/self/fd/'+str(fd),*args],fds=(fd,),check=check)
    def pair(name,bridge,fd,peer,address):
        ports.append(dict(name=name,bridge=bridge,peer=peer,inode=os.fstat(fd).st_ino,identity=None))
        save('routing-intent.json',dict(context=context_before,children=[dict(name=n,pid=p.pid,inode=os.fstat(f).st_ino) for n,p,f in children],ports=ports))
        run(['ip','link','add',name,'type','veth','peer','name',peer,'netns','/proc/self/fd/'+str(fd)],fds=(fd,))
        links=worker.links();ports[-1]['identity']=signature(links[name]);save('routing-ports.json',ports)
        worker.mutate(dict(context=context_before),'master',ports[-1]['identity'],signature(links[bridge]))
        worker.mutate(dict(context=context_before),'up',ports[-1]['identity'])
        ns(fd,['ip','link','set','lo','up']);ns(fd,['ip','link','set',peer,'up']);ns(fd,['ip','addr','add',address,'dev',peer])
    def ping(fd, target):return ns(fd,['ping','-n','-c','1','-W','1',target],check=False).returncode==0
    def require_ping(fd,target):
        for _ in range(5):
            if ping(fd,target):return
            time.sleep(.2)
        raise RuntimeError('routing target not reachable: '+target)
    try:
        g1=child('vd1');g2=child('vd2');jh=child('jumphost')
        pair('gatev1','bm1',g1,'eth0','10.1.0.2/24');pair('gatev2','bm2',g2,'eth0','10.2.0.2/24')
        pair('gatej1','bm1',jh,'eth1','10.1.0.254/24');pair('gatej2','bm2',jh,'eth2','10.2.0.254/24')
        run(['sysctl','-qw','net.ipv4.ip_forward=1']);ns(jh,['sysctl','-qw','net.ipv4.ip_forward=1'])
        for fd,gw in ((g1,'10.1.0.1'),(g2,'10.2.0.1')):ns(fd,['ip','route','replace','default','via',gw])
        require_ping(g1,'10.1.0.254');require_ping(g2,'10.2.0.254')
        probes=[['FORWARD','-i',worker.plan['vrf'],'-m','comment','--comment','dnlab-management-fixture-ingress-vrf'],
                ['FORWARD','-i','bm1','-m','comment','--comment','dnlab-management-fixture-ingress-bridge'],
                ['FORWARD','-o','bm2','-m','comment','--comment','dnlab-management-fixture-egress-bridge']]
        save('routing-probe-intent.json',probes)
        for probe in reversed(probes):run(['iptables','-w','-I',probe[0],'1',*probe[1:]])
        shortcut=ping(g1,'10.2.0.2')
        save('routing-probe-counters.json',dict(shortcut_passed=shortcut,ipv4=execute(['iptables-save','-c','-t','filter']),rules=execute(['ip','-4','rule','show'])))
        for probe in probes:run(['iptables','-w','-D',*probe])
        assert not shortcut;receipts['technical_gateway_blocked']=True
        # Positive control proves the route was viable: remove just the qualified
        # fixture-owned DROP rules, then restore their exact selectors immediately.
        drop=[rule for rule in worker.rules() if rule[-1]=='DROP']
        worker.preflight(worker.read())
        try:
            for rule in drop:run(['iptables','-w','-D',*rule])
            require_ping(g1,'10.2.0.2');receipts['positive_control_without_drop']=True
        finally:
            for rule in reversed(drop):run(['iptables','-w','-I',rule[0],'1',*rule[1:]])
        assert not ping(g1,'10.2.0.2');receipts['technical_gateway_blocked_after_restore']=True
        for fd,gw in ((g1,'10.1.0.254'),(g2,'10.2.0.254')):ns(fd,['ip','route','replace','default','via',gw])
        require_ping(g1,'10.2.0.2');require_ping(g2,'10.1.0.2');receipts['bidirectional_via_jumphost']=True
        save('routing-firewall.json',dict(ipv4=execute(['iptables-save','-t','filter']),ipv6=execute(['ip6tables-save','-t','filter'])))
        worker.preflight(worker.read())
        try:worker.cleanup()
        except ManagementError:receipts['attached_ports_block_cleanup']=True
        else:raise AssertionError('live guest ports did not block cleanup')
        return receipts
    finally:
        # Closing the child network namespaces destroys only their own pairs.
        for name,proc,fd in children:
            if proc.stdin:proc.stdin.close()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=10)
            if fd is not None:os.close(fd)
        for _ in range(100):
            current=worker.links()
            if not any(p['name'] in current for p in ports):break
            time.sleep(.05)
        else:raise RuntimeError('routing fixture peer teardown pending')
        save('routing-cleanup.json',dict(children_exited=all(p.poll() is not None for _,p,_ in children),ports_absent=not any(p['name'] in worker.links() for p in ports)))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    root=Path(args.output);root.mkdir(mode=0o700,parents=True,exist_ok=False)
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:
        raise RuntimeError('refusing host network namespace')
    def save(name,value):
        file=root/name
        with file.open('w') as stream:json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    save('intent.json',dict(context=context(),pid=os.getpid(),root=str(root),scope='isolated-management-kernel-gate',resources=['eth0','vrfa','vrfb','bm1','bm2','bm3','vm1','vm2','vm3']))
    execute(['ip','link','add','eth0','type','dummy']);execute(['ip','addr','add','192.0.2.1/24','dev','eth0']);execute(['ip','link','set','eth0','up'])
    def plan(lab,vrf,table,ids):
        return dict(lab=lab,generation=('a' if lab.endswith('alpha') else 'b')*32,vrf=vrf,table=table,
            segments={str(i):dict(bridge='bm'+str(i),vxlan='vm'+str(i),vni=70000+i,underlay='eth0',local='192.0.2.1',remotes=['192.0.2.2'],address=f'10.{1 if i==3 else i}.0.1/24') for i in ids})
    a=Worker(plan('breakout-alpha','vrfa',42000,[1,2]),directory=root/'journal')
    b=Worker(plan('breakout-beta','vrfb',42001,[3]),directory=root/'journal')
    def snapshot(w):
        r=w.read();links=w.links()
        return dict(context=context(),phase=r['phase'],resources={name:dict(identity=signature(links[name]),config=links[name].get('linkinfo'),master=links[name].get('master')) for name in w.desired()},
            fdb={s['vxlan']:json.loads(execute(['bridge','-j','fdb','show','dev',s['vxlan']])) for s in w.plan['segments'].values()},
            addresses={s['bridge']:json.loads(execute(['ip','-j','addr','show','dev',s['bridge']])) for s in w.plan['segments'].values()},
            firewall={tool:[rule for rule in rules if 'dnlab-management:'+__import__('dnlab_multinode.services.management_host',fromlist=['digest']).digest([w.key,w.plan['generation']]) in rule] for tool,rules in w.firewall(r).items()})
    from dnlab_multinode.services import netsetup
    netsetup.PATHS=SimpleNamespace(management_journal_dir=str(root/'journal'))
    class LocalTransport:
        def run_input(self,command,payload,timeout):
            result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout)
            if result.returncode:raise RuntimeError('standalone management worker failed: '+result.stderr[-3000:])
            return result.stdout
    transport=LocalTransport()
    receipts={};failed=None
    try:
        receipts['control']=netsetup.invoke(transport,'provision',b.plan)
        for attempt in range(100):
            addresses=json.loads(execute(['ip','-j','addr','show','dev','bm3']))
            if not any(x.get('tentative') for v in addresses for x in v.get('addr_info',[])):break
            time.sleep(.1)
        else:raise RuntimeError('control address readiness timed out')
        before=snapshot(b);save('control-before.json',before)
        # Durable create intent survives a response lost after the real kernel mutation.
        once=[True];original=a.kernel
        def lost(payload):
            value=original(payload)
            if payload['op']=='create' and once[0]:once[0]=False;raise RuntimeError('injected lost create ACK')
            return value
        a.kernel=lost
        try:a.ensure()
        except RuntimeError as error:
            if 'injected lost' not in str(error):raise
        else:raise AssertionError('lost create ACK not injected')
        a.kernel=original;receipts['create_recovery']=netsetup.invoke(transport,'recover',a.plan);identities={n:signature(v) for n,v in a.links().items() if n in a.desired()}
        receipts['retry']=netsetup.invoke(transport,'ensure',a.plan)
        assert {n:signature(a.links()[n]) for n in identities}==identities
        after=snapshot(b);save('control-after-operations.json',after);assert stable_snapshot(after)==stable_snapshot(before)
        receipts['routing']=routing_gate(a,root,save)
        # Shared VRF is retained until the last segment is cleaned.
        receipts['first_segment']=a.cleanup(['1']);assert signature(a.links()['vrfa'])==identities['vrfa']
        assert 'bm1' not in a.links() and 'bm2' in a.links()
        once=[True]
        def lost_delete(payload):
            value=original(payload)
            if payload['op']=='delete' and once[0]:once[0]=False;raise RuntimeError('injected lost delete ACK')
            return value
        a.kernel=lost_delete
        try:a.cleanup(['2'])
        except RuntimeError as error:
            if 'injected lost' not in str(error):raise
        else:raise AssertionError('lost delete ACK not injected')
        a.kernel=original;assert a.read()['phase']=='cleanup_pending';receipts['delete_recovery']=netsetup.invoke(transport,'recover',a.plan)
        assert not set(a.desired()) & a.links().keys()
        after=snapshot(b);save('control-after.json',after);assert stable_snapshot(after)==stable_snapshot(before)
        # Legacy collision is refused by both allocation and cleanup.
        foreign=copy.deepcopy(a.plan);foreign['generation']='c'*32;foreign['vrf']='vrfc';foreign['table']=42002
        foreign['segments']={'1':dict(bridge='bm3',vxlan='vm4',vni=70004,underlay='eth0',local='192.0.2.1',remotes=[],address='10.1.0.1/24')}
        foreign['lab']='breakout-foreign';w=Worker(foreign,directory=root/'journal')
        try:w.operate('preflight')
        except ManagementError:receipts['foreign_refused']=True
        else:raise AssertionError('foreign bridge accepted')
        after=snapshot(b);save('control-after-operations.json',after);assert stable_snapshot(after)==stable_snapshot(before)
        receipts['control_cleanup']=b.cleanup();b.operate('verify-cleaned')
    except BaseException as exc:
        failed=exc
        save('failure.json',dict(type=type(exc).__name__,error=str(exc),links=json.loads(execute(['ip','-j','-d','link','show'])),
            ipv4=execute(['iptables-save','-t','filter']),ipv6=execute(['ip6tables-save','-t','filter'])))
    finally:
        cleanup={}
        for w in (a,b):
            try:
                if w.read():cleanup[w.plan['lab']]=w.cleanup()
            except BaseException as exc:cleanup[w.plan['lab']]=dict(error=str(exc))
        save('cleanup.json',cleanup)
        links=json.loads(execute(['ip','-j','-d','link','show']))
        save('final-links.json',links)
        own=set(a.desired())|set(b.desired())
        clean=not any(v['ifname'] in own for v in links)
        save('summary.json',dict(status='failed' if failed else 'passed',cleanup_verified=clean,receipts=receipts,context=context()))
    if failed:raise failed
    if not clean:raise RuntimeError('gate cleanup incomplete')
    print(json.dumps(dict(status='passed',cleanup_verified=True,output=str(root))))


if __name__=='__main__':main()
