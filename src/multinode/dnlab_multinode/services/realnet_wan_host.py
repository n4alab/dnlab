"""Root-local shared WAN provisioning; never reconciles by deleting a network."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid


class WANError(RuntimeError):
    pass


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def execute(argv):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=40)
    if result.returncode:raise WANError('WAN command failed: '+argv[0])
    return result.stdout


def context():
    info=os.stat('/proc/self/ns/net')
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'device':info.st_dev,'inode':info.st_ino}


def config(value):
    if not isinstance(value,dict) or set(value)!={'network','bridge','subnet','gateway'}:raise WANError('complete WAN configuration required')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value['network']):raise WANError('invalid WAN network name')
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',value['bridge']):raise WANError('invalid WAN bridge name')
    try:
        subnet=ipaddress.ip_network(value['subnet'],strict=True);gateway=ipaddress.ip_address(value['gateway'])
    except ValueError:raise WANError('invalid WAN IPAM configuration') from None
    if (subnet.version!=4 or gateway.version!=4 or gateway not in subnet or gateway in (subnet.network_address,subnet.broadcast_address)
            or subnet.prefixlen>30 or gateway.is_multicast or gateway.is_unspecified):raise WANError('invalid WAN gateway/subnet')
    return dict(value,subnet=str(subnet),gateway=str(gateway))


class Worker:
    def __init__(self,value,*,directory='/var/lib/dnlab/realnet-wan',run=execute,host_context=context):
        self.config=config(value);self.directory=Path(directory);self.run=run;self.host_context=host_context
        self.key=digest(['realnet-wan-v1',self.config['network']]);self.path=self.directory/(self.key+'.json')

    def options(self):
        return {'com.docker.network.bridge.name':self.config['bridge'],
                'com.docker.network.bridge.enable_ip_masquerade':'true','com.docker.network.bridge.enable_icc':'true'}

    def labels(self,record):
        return {'org.dnlab.realnet.wan.version':'1','org.dnlab.realnet.wan.scope':self.key,
                'org.dnlab.realnet.wan.creator':record['creator'],'org.dnlab.realnet.wan.config':digest(self.config)}

    def inventory(self):
        entries=[]
        for line in self.run(['docker','network','ls','--no-trunc','--format','{{json .}}']).splitlines():
            value=json.loads(line)
            if not re.fullmatch('[0-9a-f]{64}',value.get('ID','')) or not isinstance(value.get('Name'),str):raise WANError('invalid Docker network inventory')
            entries.append(value)
        if len({v['ID'] for v in entries})!=len(entries):raise WANError('ambiguous Docker network inventory')
        return entries

    def network(self):
        found=[v for v in self.inventory() if v['Name']==self.config['network']]
        if not found:return None
        if len(found)!=1:raise WANError('ambiguous WAN network name')
        values=json.loads(self.run(['docker','network','inspect',found[0]['ID']]))
        if len(values)!=1 or values[0].get('Id')!=found[0]['ID'] or values[0].get('Name')!=self.config['network']:
            raise WANError('WAN identity changed during inspection')
        return values[0]

    def bridge(self):
        links=json.loads(self.run(['ip','-j','-d','link','show']))
        values=[v for v in links if v.get('ifname')==self.config['bridge']]
        if len(values)>1:raise WANError('ambiguous WAN bridge')
        return values[0] if values else None

    @staticmethod
    def signature(value):
        return {key:value.get(key) for key in ('ifname','ifindex','address','ifalias')}

    def read(self):
        if self.directory.resolve()!=self.directory.absolute():raise WANError('WAN journal directory is a symlink')
        if not self.directory.exists():return None
        info=self.directory.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise WANError('WAN journal directory ownership differs')
        try:fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return None
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise WANError('WAN journal ownership differs')
            value=json.load(stream)
        if (value.get('config')!=self.config or value.get('context')!=self.host_context()
                or not re.fullmatch('[0-9a-f]{32}',value.get('creator',''))
                or value.get('phase') not in ('creating','active','recovery_required')):raise WANError('WAN intent configuration/context differs')
        return value

    def save(self,record):
        fd,name=tempfile.mkstemp(dir=self.directory,prefix='.wan-')
        try:
            with os.fdopen(fd,'w') as stream:stream.write(canonical(record));stream.flush();os.fsync(stream.fileno())
            os.replace(name,self.path)
            fd=os.open(self.directory,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if os.path.exists(name):os.unlink(name)

    def verify(self,record,value):
        if value is None:raise WANError('recorded WAN is absent; explicit infrastructure recovery required')
        ipam=value.get('IPAM')
        if not isinstance(ipam,dict):raise WANError('WAN IPAM structure differs')
        normalized_ipam=dict(ipam)
        options=ipam.get('Options')
        if 'Options' in ipam and (options is None or type(options) is dict and not options):
            normalized_ipam['Options']=None
        if (value.get('Driver')!='bridge' or value.get('Scope')!='local' or value.get('Internal') is not False
                or value.get('Ingress') is not False or value.get('EnableIPv6') is not False
                or value.get('Attachable') is not False or value.get('ConfigOnly',False) is not False
                or value.get('Options')!=self.options() or value.get('Labels')!=self.labels(record)
                or normalized_ipam!={'Driver':'default','Options':None,'Config':[{'Subnet':self.config['subnet'],'Gateway':self.config['gateway']}]}
                or record.get('network_id') is not None and value.get('Id')!=record['network_id']):
            raise WANError('WAN ownership or configuration differs')
        bridge=self.bridge()
        if (not bridge or bridge.get('linkinfo',{}).get('info_kind')!='bridge' or type(bridge.get('ifindex')) is not int
                or record.get('bridge') is not None and self.signature(bridge)!=record['bridge']):
            raise WANError('WAN kernel bridge identity differs')
        addresses=json.loads(self.run(['ip','-j','address','show','dev',self.config['bridge']]))
        expected={'local':self.config['gateway'],'prefixlen':ipaddress.ip_network(self.config['subnet']).prefixlen}
        ipv4=[v for item in addresses for v in item.get('addr_info',[]) if v.get('family')=='inet']
        if len(ipv4)!=1 or any(ipv4[0].get(k)!=v for k,v in expected.items()):raise WANError('WAN kernel gateway differs')
        return bridge

    def absent(self):
        if self.network() is not None:raise WANError('unqualified WAN exists; refusing adoption')
        if self.bridge() is not None:raise WANError('WAN bridge name occupied')
        # Refuse bridge-name or subnet conflicts before journal/create.
        for item in self.inventory():
            values=json.loads(self.run(['docker','network','inspect',item['ID']]))
            if len(values)!=1 or values[0].get('Id')!=item['ID']:raise WANError('network inventory changed')
            other=values[0]
            if other.get('Options',{}).get('com.docker.network.bridge.name')==self.config['bridge']:raise WANError('WAN bridge name reserved by another network')
            for entry in other.get('IPAM',{}).get('Config') or []:
                if entry.get('Subnet'):
                    subnet=ipaddress.ip_network(entry['Subnet'])
                    if subnet.version==4 and subnet.overlaps(ipaddress.ip_network(self.config['subnet'])):raise WANError('WAN subnet overlaps another Docker network')

    def preflight(self):
        record=self.read();value=self.network()
        if record:
            if record['phase']!='active':raise WANError('WAN intent needs explicit recovery')
            self.verify(record,value)
        else:self.absent()
        return {'status':'verified','network_id':value['Id'] if value else None}

    def operate(self,action='ensure'):
        if action not in ('ensure','recover'):raise WANError('unsupported WAN action')
        if self.directory.resolve()!=self.directory.absolute():raise WANError('WAN journal directory is a symlink')
        self.directory.mkdir(parents=True,mode=0o700,exist_ok=True)
        if self.directory.stat().st_uid!=0 or stat.S_IMODE(self.directory.stat().st_mode)!=0o700:raise WANError('WAN journal directory ownership differs')
        fd=os.open(self.directory/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise WANError('WAN lock ownership differs')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise WANError('WAN infrastructure operation busy') from None
            record=self.read();value=self.network()
            if record and record['phase']=='active':
                self.verify(record,value);return {'status':'active','network_id':value['Id'],'creator':record['creator']}
            if record:
                if action!='recover':raise WANError('WAN intent needs explicit recovery')
                if value is not None:
                    bridge=self.verify(record,value)
                    record.update(phase='active',network_id=value['Id'],bridge=self.signature(bridge));self.save(record)
                    return {'status':'active','network_id':value['Id'],'creator':record['creator']}
                if record.get('network_id') is not None:raise WANError('recorded WAN disappeared; refusing recreation')
            elif action=='recover':raise WANError('WAN intent missing; refusing adoption')
            self.absent()
            if not record:
                record={'config':self.config,'context':self.host_context(),'creator':uuid.uuid4().hex,'phase':'creating','network_id':None,'bridge':None}
            record['phase']='creating';self.save(record)
            args=['docker','network','create','--driver','bridge','--subnet',self.config['subnet'],'--gateway',self.config['gateway']]
            for key,value in self.options().items():args+=['--opt',key+'='+value]
            for key,value in self.labels(record).items():args+=['--label',key+'='+value]
            args.append(self.config['network'])
            try:
                self.run(args)
                value=self.network();bridge=self.verify(record,value)
                record.update(phase='active',network_id=value['Id'],bridge=self.signature(bridge));self.save(record)
                return {'status':'active','network_id':value['Id'],'creator':record['creator']}
            except Exception:
                record['phase']='recovery_required';self.save(record);raise
        finally:os.close(fd)


def main():
    if os.getuid()!=0:raise WANError('root WAN worker required')
    action,encoded=sys.argv[1:];worker=Worker(json.loads(encoded))
    print(json.dumps(worker.preflight() if action=='preflight' else worker.operate(action)))


if __name__=='__main__':main()
