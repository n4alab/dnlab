"""Standalone owned RealNet router bootstrap; never moves an existing NIC."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

from .realnet_cleanup_host import OwnershipError,Worker,context,digest,link_identity


def run_command(argv,*,pass_fds=()):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=30,pass_fds=pass_fds)
    if result.returncode:raise OwnershipError('RealNet bootstrap command failed: '+argv[0])
    return result.stdout.strip()


def creator_mac(creator,side):
    data=bytearray(hashlib.sha256((creator+side).encode()).digest()[:6]);data[0]=(data[0]&0xfc)|2
    return ':'.join(f'{part:02x}' for part in data)


class Bootstrap:
    def __init__(self,request,*,run=run_command,host_context=context,directory='/var/lib/dnlab/realnet-bootstrap'):
        if set(request)!={'infrastructure','bridge','endpoint','container','image','network','environment','ip'}:
            raise OwnershipError('invalid RealNet bootstrap request')
        self.request,self.run,self.host_context=request,run,host_context
        self.infrastructure=request['infrastructure']
        self.store=Worker(self.infrastructure,run=run,host_context=host_context,directory=directory)
        if (request['bridge'] not in self.infrastructure['links'] or self.infrastructure['links'][request['bridge']]['kind']!='bridge'
                or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',request['endpoint'])
                or request['endpoint'] in self.infrastructure['links']
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',request['container'])
                or not isinstance(request['environment'],dict)):
            raise OwnershipError('invalid RealNet bootstrap resources')
        if set(request['environment'])!={'REALNET_IPV4','NAT_ENABLED','BGP_ENABLED','BGP_ROUTER_ID'}:
            raise OwnershipError('invalid RealNet helper environment')
        self.directory=self.store.directory

    def host_links(self):return json.loads(self.run(['ip','-j','-d','link','show']))

    def inspect(self):
        name=self.request['container']
        identity=self.run(['docker','ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).strip()
        if not identity:return None
        if not re.fullmatch('[0-9a-f]{64}',identity):raise OwnershipError('ambiguous RealNet helper identity')
        value=json.loads(self.run(['docker','inspect',identity]))[0]
        if value['Id']!=identity or value['Name']!='/'+name:raise OwnershipError('RealNet helper was replaced')
        return value

    def descriptor(self):
        image=json.loads(self.run(['docker','image','inspect',self.request['image']]))[0]
        network=json.loads(self.run(['docker','network','inspect',self.request['network']]))[0]
        if not re.fullmatch('sha256:[0-9a-f]{64}',image['Id']) or not re.fullmatch('[0-9a-f]{64}',network['Id']):
            raise OwnershipError('immutable RealNet image/network required')
        return {**self.request,'image_id':image['Id'],'image_command':{key:image['Config'].get(key) for key in ('Entrypoint','Cmd')},'network_id':network['Id']}

    def verify_infrastructure(self,record):
        if self.host_context()!=self.infrastructure['context']:raise OwnershipError('RealNet host namespace changed')
        links=self.host_links();current={value['ifname']:value for value in links}
        for name,expected in self.infrastructure['links'].items():
            value=current.get(name)
            if (value is None or link_identity(value)!=expected['identity'] or value.get('linkinfo',{}).get('info_kind')!=expected['kind']
                    or any(value.get('linkinfo',{}).get('info_data',{}).get(key)!=wanted for key,wanted in expected['config'].items())):
                raise OwnershipError('RealNet infrastructure is unqualified or changed')
        endpoint=current.get(self.request['endpoint'])
        if endpoint:
            if (not record or record['steps'].get('allocate') not in ('intent','done')
                    or endpoint.get('address')!=creator_mac(record['creator'],'host')
                    or endpoint.get('linkinfo',{}).get('info_kind')!='veth'):
                raise OwnershipError('foreign RealNet host endpoint')
            alias='dnlab-runtime:realnet:'+self.infrastructure['scope']+':'+record['creator']
            if endpoint.get('ifalias') not in (None,'',alias):raise OwnershipError('RealNet endpoint alias differs')
            bridge=current[self.request['bridge']]
            if endpoint.get('master') not in (None,bridge['ifname'],bridge['ifindex']):
                raise OwnershipError('RealNet endpoint belongs to another bridge')
            if record.get('host_link') and link_identity(endpoint)!=record['host_link']['identity']:
                raise OwnershipError('RealNet host endpoint was replaced')
        bridge=current[self.request['bridge']]
        allowed=set(self.infrastructure['links'])|({self.request['endpoint']} if endpoint else set())
        for port in links:
            if port.get('master') in (bridge['ifindex'],bridge['ifname']) and port['ifname'] not in allowed:
                raise OwnershipError('RealNet bridge has an unqualified port')
        self.store.firewall()
        return current

    def verify_container(self,value,descriptor,record):
        labels=value.get('Config',{}).get('Labels') or {}
        expected={'org.dnlab.realnet.scope':self.infrastructure['scope'],
                  'org.dnlab.realnet.creator':record['creator'],'org.dnlab.realnet.config':digest(descriptor)}
        if (value['Image']!=descriptor['image_id'] or any(labels.get(key)!=wanted for key,wanted in expected.items())
                or record.get('container_id') not in (None,value['Id'])
                or value['State'].get('Running') is not True or type(value['State'].get('Pid')) is not int or value['State']['Pid']<=0
                or value.get('HostConfig',{}).get('Privileged') is not True
                or not any(cap in ('NET_ADMIN','CAP_NET_ADMIN') for cap in value['HostConfig'].get('CapAdd',[]))
                or any(value['Config'].get(key)!=wanted for key,wanted in descriptor['image_command'].items())):
            raise OwnershipError('RealNet helper ownership/configuration differs; explicit recovery required')
        networks=value.get('NetworkSettings',{}).get('Networks',{})
        if set(networks)!={self.request['network']} or networks[self.request['network']].get('NetworkID')!=descriptor['network_id']:
            raise OwnershipError('RealNet helper network differs')
        if self.request['ip'] and networks[self.request['network']].get('IPAddress')!=self.request['ip']:
            raise OwnershipError('RealNet helper IP differs')
        for key,wanted in self.request['environment'].items():
            if [entry for entry in value['Config'].get('Env',[]) if entry.startswith(key+'=')]!=[key+'='+wanted]:
                raise OwnershipError('RealNet helper environment differs')

    def save(self,path,record):self.store.save(path,record)

    def deploy(self):
        descriptor=self.descriptor()
        if self.directory.resolve()!=self.directory.absolute():raise OwnershipError('RealNet bootstrap directory is a symlink')
        path=self.directory/(self.infrastructure['scope']+'.json')
        record=self.store.read(path)
        if record and record.get('descriptor')!=descriptor:raise OwnershipError('RealNet bootstrap configuration changed')
        self.verify_infrastructure(record)
        existing=self.inspect()
        if existing and not record:raise OwnershipError('unqualified existing RealNet helper')
        if existing:self.verify_container(existing,descriptor,record)
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.directory.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise OwnershipError('RealNet bootstrap directory ownership/mode differs')
        lock=os.open(self.directory/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(lock)
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:raise OwnershipError('RealNet bootstrap lock differs')
            fcntl.flock(lock,fcntl.LOCK_EX)
            record=self.store.read(path)
            if record and record.get('descriptor')!=descriptor:raise OwnershipError('RealNet bootstrap configuration changed')
            self.verify_infrastructure(record)
            existing=self.inspect()
            if existing and not record:raise OwnershipError('unqualified existing RealNet helper')
            record=record or {'proof':self.infrastructure,'descriptor':descriptor,'creator':uuid.uuid4().hex,'phase':'applying','steps':{}}
            if existing:self.verify_container(existing,descriptor,record)
            self.save(path,record)
            if existing is None:
                if record.get('container_id'):raise OwnershipError('RealNet helper disappeared; explicit recovery required')
                record['steps']['container']='intent';self.save(path,record)
                args=['docker','run','-d','--name',self.request['container'],'--hostname',self.request['container'],
                      '--privileged','--cap-add','NET_ADMIN','--network',self.request['network']]
                if self.request['ip']:args+=['--ip',self.request['ip']]
                for key,value in self.request['environment'].items():args+=['-e',key+'='+value]
                for key,value in {'org.dnlab.realnet.scope':self.infrastructure['scope'],'org.dnlab.realnet.creator':record['creator'],
                                  'org.dnlab.realnet.config':digest(descriptor)}.items():args+=['--label',key+'='+value]
                self.run([*args,descriptor['image_id']]);existing=self.inspect()
                self.verify_container(existing,descriptor,record)
            record['container_id']=existing['Id'];record['steps']['container']='done';self.save(path,record)
            fd=os.open('/proc/'+str(existing['State']['Pid'])+'/ns/net',os.O_RDONLY)
            try:
                info=os.fstat(fd);namespace={'device':info.st_dev,'inode':info.st_ino}
                if record.get('namespace') not in (None,namespace):raise OwnershipError('RealNet helper namespace changed')
                record['namespace']=namespace;self.save(path,record)
                prefix=['nsenter','--net=/proc/self/fd/'+str(fd),'--']
                def peers():return json.loads(self.run([*prefix,'ip','-j','-d','link','show'],pass_fds=(fd,)))
                def verify_live():
                    value=self.inspect();self.verify_container(value,descriptor,record)
                    info=os.stat('/proc/'+str(value['State']['Pid'])+'/ns/net')
                    if {'device':info.st_dev,'inode':info.st_ino}!=namespace:raise OwnershipError('RealNet helper namespace changed')
                    return self.verify_infrastructure(record)
                links=verify_live();peer=next((x for x in peers() if x['ifname']=='eth1'),None)
                endpoint=links.get(self.request['endpoint'])
                if peer is not None and (endpoint is None or peer.get('address')!=creator_mac(record['creator'],'peer')):
                    raise OwnershipError('foreign helper LAN port')
                if endpoint is None:
                    if record['steps'].get('allocate')=='done':raise OwnershipError('RealNet endpoint disappeared; explicit recovery required')
                    record['steps']['allocate']='intent';self.save(path,record)
                    self.run(['ip','link','add',self.request['endpoint'],'address',creator_mac(record['creator'],'host'),
                              'type','veth','peer','name','eth1','address',creator_mac(record['creator'],'peer'),
                              'netns','/proc/self/fd/'+str(fd)],pass_fds=(fd,))
                links=verify_live();endpoint=links[self.request['endpoint']];peer=next((x for x in peers() if x['ifname']=='eth1'),None)
                if (peer is None or peer.get('address')!=creator_mac(record['creator'],'peer')
                        or endpoint.get('link_index')!=peer.get('ifindex') or peer.get('link_index')!=endpoint.get('ifindex')
                        or peer.get('linkinfo',{}).get('info_kind')!='veth'):
                    raise OwnershipError('RealNet veth reciprocal peer differs')
                if record['phase']=='active':
                    if link_identity(peer)!=record['peer_identity'] or endpoint.get('master') not in (self.request['bridge'],links[self.request['bridge']]['ifindex']):
                        raise OwnershipError('active RealNet endpoint configuration changed')
                    return self.result(record,existing)
                record['steps']['allocate']='done';self.save(path,record)
                alias='dnlab-runtime:realnet:'+self.infrastructure['scope']+':'+record['creator']
                record['steps']['attach']='intent';self.save(path,record)
                for args,fds in [(['ip','link','set','dev',self.request['endpoint'],'alias',alias],()),
                                  ([*prefix,'ip','link','set','dev','eth1','alias',alias],(fd,)),
                                  (['ip','link','set','dev',self.request['endpoint'],'master',self.request['bridge']],()),
                                  (['ip','link','set','dev',self.request['endpoint'],'up'],()),
                                  ([*prefix,'ip','link','set','dev','eth1','up'],(fd,))]:
                    verify_live();self.run(args,pass_fds=fds)
                endpoint=verify_live()[self.request['endpoint']];peer=next(x for x in peers() if x['ifname']=='eth1')
                record['host_link']={'kind':'veth','identity':link_identity(endpoint),'config':{}}
                record['peer_identity']=link_identity(peer);record['steps']['attach']='done';record['phase']='active'
                self.save(path,record)
                return self.result(record,existing)
            finally:os.close(fd)
        finally:os.close(lock)

    def result(self,record,container):
        return {'phase':'active','container_id':container['Id'],'host_link':record['host_link'],
                'router':{'id':container['Id'],'name':self.request['container'],'image':container['Image'],'labels':container['Config']['Labels']},
                'namespace':record['namespace'],'peer_identity':record['peer_identity'],
                'wan_ip':container['NetworkSettings']['Networks'][self.request['network']].get('IPAddress','')}


def main():
    print(json.dumps(Bootstrap(json.loads(sys.argv[1])).deploy()))


if __name__=='__main__':main()
