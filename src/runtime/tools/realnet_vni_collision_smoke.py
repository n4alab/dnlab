#!/usr/bin/env python3
"""Diagnose RealNet VNI collisions only inside dedicated network namespaces."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid


def run(different_remote=False):
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-vni-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:8]
    names={role:'drsp-rnv-'+token+'-'+role for role in ('m','w','am','aw','bm','bw')}
    owned={}
    report={'scope':'isolated-RealNet-VNI-collision-diagnosis','status':'running',
            'vni':5271,'udp_port':14789,'runtime_changed':False,'production_network_touched':False,
            'different_remote':different_remote}
    def command(argv,check=True):
        result=subprocess.run(argv,text=True,capture_output=True,timeout=15)
        if check and result.returncode:
            raise RuntimeError('fixture command failed: '+argv[0]+' '+result.stderr.strip())
        return result
    def verify(role):
        info=os.stat('/var/run/netns/'+names[role])
        if (info.st_dev,info.st_ino)!=owned[role]:raise RuntimeError('fixture namespace ownership changed')
    def ns(role,*argv,check=True):
        verify(role)
        return command(['ip','netns','exec',names[role],*argv],check=check)
    def inventory(role):return json.loads(ns(role,'ip','-j','-d','link','show').stdout)
    def save(name,value):(root/name).write_text(json.dumps(value,indent=2)+'\n')
    def alias(role,device):ns(role,'ip','link','set','dev',device,'alias','drsp-realnet-vni:'+token+':'+role+':'+device)
    def endpoint(host,guest,lab,address):
        verify(guest)
        port=lab+'-port'
        ns(host,'ip','link','add',port,'type','veth','peer','name','data0','netns',names[guest])
        alias(host,port);alias(guest,'data0')
        ns(host,'ip','link','set',port,'master','br-'+lab);ns(host,'ip','link','set',port,'up')
        ns(guest,'ip','addr','add',address+'/24','dev','data0');ns(guest,'ip','link','set','data0','up')
    def tunnel(host,lab):
        local,remote=('198.18.0.1','198.18.0.2') if host=='m' else ('198.18.0.2','198.18.0.1')
        if lab=='b' and different_remote:remote='198.18.0.3' if host=='m' else '198.18.0.4'
        result=ns(host,'ip','link','add','vx-'+lab,'type','vxlan','id','5271','remote',remote,
                  'local',local,'dstport','14789','dev','under0',check=False)
        save('create-'+host+'-'+lab+'.json',{'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode==0:
            alias(host,'vx-'+lab);ns(host,'ip','link','set','vx-'+lab,'master','br-'+lab)
            ns(host,'ip','link','set','vx-'+lab,'up')
        return {'host':host,'local':local,'remote':remote,'returncode':result.returncode,'stderr':result.stderr.strip()}
    def ping(guest,target):
        result=ns(guest,'ping','-n','-c','2','-W','1',target,check=False)
        return {'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    def tunnel_identity(role):
        link=next(value for value in inventory(role) if value['ifname']=='vx-a')
        return {key:link.get(key) for key in ('ifname','ifindex','address','ifalias','master','flags','mtu')},link['linkinfo']['info_data']
    try:
        for role,name in names.items():
            if Path('/var/run/netns',name).exists():raise RuntimeError('fixture namespace exists')
            command(['ip','netns','add',name])
            info=os.stat('/var/run/netns/'+name);owned[role]=(info.st_dev,info.st_ino)
            ns(role,'ip','link','set','lo','up')
        ns('m','ip','link','add','under0','type','veth','peer','name','under0','netns',names['w'])
        for host,address in (('m','198.18.0.1'),('w','198.18.0.2')):
            alias(host,'under0');ns(host,'ip','addr','add',address+'/24','dev','under0');ns(host,'ip','link','set','under0','up')
            for lab,mac in (('a','02:00:00:00:00:01'),('b','02:00:00:00:00:02')):
                ns(host,'ip','link','add','br-'+lab,'address',mac,'type','bridge')
                alias(host,'br-'+lab);ns(host,'ip','link','set','br-'+lab,'up')
        first=[tunnel(host,'a') for host in ('m','w')]
        assert all(value['returncode']==0 for value in first),first
        endpoint('m','am','a','192.0.2.1');endpoint('w','aw','a','192.0.2.2')
        before={host:inventory(host) for host in ('m','w')};save('before-second-lab.json',before)
        identities={host:tunnel_identity(host) for host in ('m','w')}
        initial=ping('am','192.0.2.2');save('first-lab-traffic-before.json',initial)
        assert initial['returncode']==0,initial
        second=[tunnel(host,'b') for host in ('m','w')]
        report['second_tunnel_results']=second
        after={host:inventory(host) for host in ('m','w')};save('after-second-lab.json',after)
        report['first_tunnel_identity_and_config_unchanged']=all(tunnel_identity(host)==identities[host] for host in ('m','w'))
        assert report['first_tunnel_identity_and_config_unchanged']
        final=ping('am','192.0.2.2');save('first-lab-traffic-after.json',final)
        report['first_lab_traffic_before_and_after_passed']=initial['returncode']==final['returncode']==0
        assert report['first_lab_traffic_before_and_after_passed']
        if all(value['returncode']==0 for value in second) and not different_remote:
            endpoint('m','bm','b','192.0.2.11');endpoint('w','bw','b','192.0.2.12')
            same_lab=ping('bm','192.0.2.12');cross_lab=ping('am','192.0.2.12')
            save('second-lab-traffic.json',same_lab);save('cross-lab-traffic.json',cross_lab)
            report['second_lab_traffic_passed']=same_lab['returncode']==0
            report['cross_lab_traffic_observed']=cross_lab['returncode']==0
        else:
            report['cross_lab_traffic_observed']=None
            report['cross_lab_traffic_not_tested_reason']='Different remote has no fixture endpoint' if different_remote else 'Second lab cannot create both tunnels'
        report['status']='diagnosed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error)
        raise
    finally:
        try:
            for role in reversed(list(owned)):
                verify(role);command(['ip','netns','delete',names[role]])
                assert not Path('/var/run/netns',names[role]).exists()
            report['cleanup_verified']=True
        except BaseException as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);raise
        finally:
            save('report.json',report)
            print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified')}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--different-remote',action='store_true',help='Diagnose same VNI/local/port/device with a different remote peer')
    args=parser.parse_args()
    if not args.execute:print(json.dumps({'mutations_performed':False,'creates':'six dedicated namespaces, isolated underlay/bridges/veth/VXLAN; no containers'}))
    elif os.geteuid()!=0:raise RuntimeError('fixture requires root')
    else:run(args.different_remote)
