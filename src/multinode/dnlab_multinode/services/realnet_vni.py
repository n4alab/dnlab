"""Coordinator-owned RealNet VNI reservations; no scheduling or topology store."""
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import uuid

from .paths import PATHS
from .realnet_cleanup import scope
from .realnet_cleanup_host import OwnershipError,link_identity,validate

INVENTORY_PROGRAM="""import json,os,subprocess
from pathlib import Path
p=os.stat('/proc/self/ns/net')
links=json.loads(subprocess.check_output(['ip','-j','-d','link','show'],text=True))
print(json.dumps({'context':{'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'device':p.st_dev,'inode':p.st_ino},'links':links}))
"""


def identity_key(identity):
    if (isinstance(identity,list) and len(identity)==4 and identity[1]=='management'
            and identity[3]=='multipoint' and all(isinstance(v,str) and v for v in identity)):
        return hashlib.sha256(json.dumps(['management-vni-v1',*identity],separators=(',',':')).encode()).hexdigest()
    if (not isinstance(identity,list) or len(identity)!=3 or any(not isinstance(v,str) or not v for v in identity)
            or identity[2]=='master'):
        raise OwnershipError('invalid RealNet VNI identity')
    return hashlib.sha256(json.dumps(['realnet-vni-v1',*identity],separators=(',',':')).encode()).hexdigest()


def snapshots(clients,hosts):
    result={}
    for host in sorted(hosts):
        if host not in clients:raise OwnershipError('RealNet VNI preflight host unavailable: '+host)
        try:value=json.loads(clients[host].run(shlex.join(['python3','-c',INVENTORY_PROGRAM])))
        except Exception:raise OwnershipError('RealNet VNI inventory failed: '+host) from None
        if (not isinstance(value,dict) or set(value)!={'context','links'}
                or set(value['context'])!={'boot_id','device','inode'} or not isinstance(value['links'],list)
                or len({link['ifname'] for link in value['links']})!=len(value['links'])):
            raise OwnershipError('invalid RealNet VNI inventory: '+host)
        result[host]=value
    return result


class Registry:
    def __init__(self,directory=None,*,pool=(65536,16777215)):
        self.directory=Path(directory if directory is not None else PATHS.realnet_vni_dir)
        if len(pool)!=2 or any(type(v) is not int for v in pool) or not 1<=pool[0]<=pool[1]<=16777215:
            raise OwnershipError('invalid RealNet VNI pool')
        self.pool=tuple(pool)

    @contextmanager
    def locked(self):
        if self.directory.resolve()!=self.directory.absolute():raise OwnershipError('RealNet VNI registry path is a symlink')
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.directory.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise OwnershipError('RealNet VNI registry ownership/mode differs')
        fd=os.open(self.directory/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:
                raise OwnershipError('RealNet VNI lock ownership/mode differs')
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:os.close(fd)

    def read(self):
        try:fd=os.open(self.directory/'registry.json',os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return {'version':1,'pool':list(self.pool),'reservations':{}}
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno())
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:
                raise OwnershipError('RealNet VNI registry file ownership/mode differs')
            value=json.load(stream)
        if (set(value)!={'version','pool','reservations'} or value['version']!=1
                or value['pool']!=list(self.pool) or not isinstance(value['reservations'],dict)):
            raise OwnershipError('RealNet VNI registry format differs')
        used=set()
        for key,row in value['reservations'].items():
            if (set(row)!={'identity','targets','vni','token','phase'} or key!=identity_key(row['identity'])
                    or type(row['vni']) is not int or not self.pool[0]<=row['vni']<=self.pool[1]
                    or not re.fullmatch('[0-9a-f]{32}',row['token']) or row['phase'] not in ('reserved','released')):
                raise OwnershipError('invalid RealNet VNI reservation')
            self.validate_targets(row['identity'],row['targets'])
            if row['phase']!='released':
                if row['vni'] in used:raise OwnershipError('duplicate reserved RealNet VNI')
                used.add(row['vni'])
        return value

    def save(self,value):
        fd,name=tempfile.mkstemp(prefix='.registry-',dir=self.directory)
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
            os.replace(name,self.directory/'registry.json')
            fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if os.path.exists(name):os.unlink(name)

    def validate_targets(self,identity,targets):
        if len(identity)==4:
            if not isinstance(targets,dict) or not targets:raise OwnershipError('management VNI hosts required')
            for host,target in targets.items():
                if not isinstance(host,str) or not host or set(target)!={'name','bridge','local','remotes','underlay','dstport'}:
                    raise OwnershipError('invalid management VNI target')
                if any(not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',target[k]) for k in ('name','bridge','underlay')) or target['dstport']!=4789:
                    raise OwnershipError('invalid management VNI target configuration')
                ipaddress.IPv4Address(target['local'])
                if not isinstance(target['remotes'],list) or sorted(target['remotes'])!=sorted(t['local'] for h,t in targets.items() if h!=host):
                    raise OwnershipError('management VNI peer inventory differs')
            return
        if not isinstance(targets,dict) or set(targets)!={'master',identity[2]}:
            raise OwnershipError('invalid RealNet VNI host pair')
        for target in targets.values():
            if (set(target)!={'name','bridge','local','remote','underlay','dstport'}
                    or any(not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',target[k]) for k in ('name','bridge','underlay'))
                    or target['dstport']!=14789):raise OwnershipError('invalid RealNet VNI target')
            for key in ('local','remote'):ipaddress.ip_address(target[key])
        master,worker=targets['master'],targets[identity[2]]
        if master['local']!=worker['remote'] or worker['local']!=master['remote']:
            raise OwnershipError('RealNet VNI endpoint addresses disagree')

    def candidate(self,key):return self.pool[0]+int(key,16)%(self.pool[1]-self.pool[0]+1)

    def metadata(self,key,row):return {'key':key,'token':row['token'],'vni':row['vni']}

    def verify_target(self,request,row,host,snapshot):
        if len(request['identity'])==4:
            from .management_host import signature
            target=request['targets'][host];links={v['ifname']:v for v in snapshot['links']}
            proof=request.get('proofs',{}).get(host)
            for name in (target['bridge'],target['name']):
                current=links.get(name)
                if current is None:continue
                expected=(proof or {}).get('resources',{}).get(name,{}).get('identity')
                if not row or request.get('previous')!=self.metadata(identity_key(request['identity']),row) or not expected or signature(current)!=expected or proof.get('context')!=snapshot['context']:
                    raise OwnershipError('management VNI target requires durable birth proof')
            current=links.get(target['name'])
            if current:
                data=current.get('linkinfo',{}).get('info_data',{})
                if data.get('id')!=row['vni'] or data.get('local')!=target['local'] or data.get('port')!=4789:
                    raise OwnershipError('management VNI target configuration differs')
            return current is not None
        target=request['targets'][host];links={v['ifname']:v for v in snapshot['links']}
        current=links.get(target['name']);bridge=links.get(target['bridge'])
        proof=request.get('proofs',{}).get(host)
        if proof is not None:
            validate(proof)
            if proof['scope']!=scope(request['identity'][0],request['identity'][1],host) or proof['context']!=snapshot['context']:
                raise OwnershipError('RealNet VNI host ownership context differs')
        if bridge is None and target['bridge'] in (proof or {}).get('links',{}):
            raise OwnershipError('owned RealNet bridge disappeared; recovery required')
        if bridge is not None:
            expected=(proof or {}).get('links',{}).get(target['bridge'])
            if (not expected or expected['kind']!='bridge' or link_identity(bridge)!=expected['identity']
                    or bridge.get('linkinfo',{}).get('info_kind')!='bridge'):
                raise OwnershipError('RealNet VNI bridge requires qualified ownership')
        expected=(proof or {}).get('links',{}).get(target['name'])
        if current is None:
            if expected:raise OwnershipError('owned RealNet VXLAN disappeared; recovery required')
            return False
        if row is None or request.get('previous')!=self.metadata(identity_key(request['identity']),row) or not expected:
            raise OwnershipError('RealNet VNI target is unqualified or legacy')
        data=current.get('linkinfo',{}).get('info_data',{})
        underlay=links.get(target['underlay'])
        if (expected['kind']!='vxlan' or link_identity(current)!=expected['identity']
                or current.get('linkinfo',{}).get('info_kind')!='vxlan'
                or data.get('id')!=row['vni'] or data.get('local')!=target['local']
                or data.get('remote')!=target['remote'] or data.get('port')!=target['dstport']
                or not underlay or data.get('link') not in (target['underlay'],underlay['ifindex'])
                or current.get('master') not in (target['bridge'],bridge['ifindex'] if bridge else None)):
            raise OwnershipError('RealNet VNI target ownership/configuration differs')
        return True

    def reserve(self,requests,inventory):
        requests=copy.deepcopy(requests)
        keys=[identity_key(r['identity']) for r in requests]
        if len(set(keys))!=len(keys):raise OwnershipError('duplicate RealNet VNI request')
        for request in requests:self.validate_targets(request['identity'],request['targets'])
        named=[(host,target['name']) for request in requests for host,target in request['targets'].items()]
        if len(set(named))!=len(named):raise OwnershipError('duplicate planned RealNet VXLAN name')
        if not requests:return {}
        with self.locked():
            original=self.read();value=copy.deepcopy(original)
            # All host reads complete before a reservation is committed or any caller mutates hosts.
            observed=inventory({host for r in requests for host in r['targets']})
            if set(observed)!={host for r in requests for host in r['targets']}:
                raise OwnershipError('incomplete RealNet VNI host preflight')
            occupied=set()
            for snapshot in observed.values():
                for link in snapshot['links']:
                    if link.get('linkinfo',{}).get('info_kind')!='vxlan':continue
                    vni=link['linkinfo'].get('info_data',{}).get('id')
                    if type(vni) is not int or not 1<=vni<=16777215:
                        raise OwnershipError('invalid VXLAN VNI in host inventory')
                    occupied.add(vni)
            used={r['vni'] for r in value['reservations'].values() if r['phase']!='released'}|occupied
            result={}
            for key,request in sorted(zip(keys,requests)):
                row=value['reservations'].get(key)
                if row and row['phase']=='released':row=None
                if request.get('previous') is not None and (row is None or request['previous']!=self.metadata(key,row)):
                    raise OwnershipError('RealNet VNI reservation generation differs')
                if row and (row['identity']!=request['identity'] or row['targets']!=request['targets']):
                    if len(request['identity'])!=4 or row['identity']!=request['identity'] or not set(row['targets'])<=request['targets'].keys():
                        raise OwnershipError('reserved RealNet VNI topology changed; recovery required')
                    for host,old in row['targets'].items():
                        new=request['targets'][host]
                        if ({k:v for k,v in old.items() if k!='remotes'}!={k:v for k,v in new.items() if k!='remotes'}
                                or not set(old['remotes'])<=set(new['remotes'])):
                            raise OwnershipError('reserved management VNI endpoint changed')
                    row['targets']=copy.deepcopy(request['targets'])
                for other_key,other in value['reservations'].items():
                    if other_key==key or other['phase']=='released':continue
                    for host,target in request['targets'].items():
                        if host in other['targets'] and target['name']==other['targets'][host]['name']:
                            raise OwnershipError('RealNet VXLAN name is reserved by another identity')
                owned_names={host:[] for host in request['targets']}
                for host in request['targets']:
                    if self.verify_target(request,row,host,observed[host]):owned_names[host].append(request['targets'][host]['name'])
                if row:
                    for host,snapshot in observed.items():
                        for link in snapshot['links']:
                            if (link.get('linkinfo',{}).get('info_kind')=='vxlan'
                                    and link['linkinfo']['info_data']['id']==row['vni'] and link['ifname'] not in owned_names.get(host,[])):
                                raise OwnershipError('reserved RealNet VNI conflicts with another tunnel; active VNI unchanged')
                else:
                    candidate=self.candidate(key);width=self.pool[1]-self.pool[0]+1
                    for offset in range(width):
                        vni=self.pool[0]+(candidate-self.pool[0]+offset)%width
                        if vni not in used:break
                    else:raise OwnershipError('RealNet VNI pool exhausted')
                    row={'identity':request['identity'],'targets':request['targets'],'vni':vni,'token':uuid.uuid4().hex,'phase':'reserved'}
                    value['reservations'][key]=row;used.add(vni)
                result[key]=self.metadata(key,row)
            if value!=original:self.save(value)
            return result

    def release(self,metadata,verify_cleanup):
        with self.locked():
            original=self.read();value=copy.deepcopy(original)
            for item in metadata:
                row=value['reservations'].get(item['key'])
                if not row or self.metadata(item['key'],row)!=item:
                    raise OwnershipError('RealNet VNI release generation differs')
            # The callback must validate authoritative remote cleanup journals, not a caller boolean.
            verify_cleanup()
            for item in metadata:value['reservations'][item['key']]['phase']='released'
            if value!=original:self.save(value)


def reserve_realnets(topo,clients,underlay_ips,states,*,directory=None):
    requests=[]
    for state in states:
        previous=state.resource_identities.get('realnet_vni_v1',{})
        workers=sorted(host for host in state.hosts if host!='master')
        if len(workers)!=len(state.vxlan_ifaces.get('master',[])):
            raise OwnershipError('RealNet VNI peer inventory differs')
        for worker,peer in zip(workers,state.vxlan_ifaces.get('master',[])):
            targets={host:{'name':peer if host=='master' else state.vxlan_ifaces[worker][0],
                           'bridge':state.bridge,'local':underlay_ips[host],
                           'remote':underlay_ips[worker if host=='master' else 'master'],
                           'underlay':topo.underlay_iface,'dstport':14789} for host in ('master',worker)}
            requests.append({'identity':[topo.name,state.name,worker],'targets':targets,
                             'previous':previous.get(worker),'proofs':state.resource_identities.get('realnet_cleanup_v1',{})})
    allocated=Registry(directory).reserve(requests,lambda hosts:snapshots(clients,hosts))
    for state in states:
        metadata={worker:allocated[identity_key([topo.name,state.name,worker])] for worker in state.hosts if worker!='master'}
        state.vxlan_ids={worker:row['vni'] for worker,row in metadata.items()}
        state.vxlan_id=next(iter(state.vxlan_ids.values()),0)
        if metadata:state.resource_identities['realnet_vni_v1']=metadata
    return allocated


def release_realnets(lab,clients,states,*,directory=None):
    metadata=[]
    for state in states:
        reservations=state.resource_identities.get('realnet_vni_v1',{})
        if not reservations:continue
        if set(reservations)!={host for host in state.hosts if host!='master'}:
            raise OwnershipError('RealNet VNI release peer inventory differs')
        for worker,item in reservations.items():
            if item.get('key')!=identity_key([lab,state.name,worker]) or item.get('vni')!=state.vxlan_ids.get(worker):
                raise OwnershipError('RealNet VNI release identity differs')
            metadata.append(item)
    if not metadata:return
    from .realnet_cleanup import verify_realnets_cleaned
    Registry(directory).release(metadata,lambda:verify_realnets_cleaned(lab,clients,states))
