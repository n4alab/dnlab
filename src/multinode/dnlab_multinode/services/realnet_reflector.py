"""Persistent shared RealNet reflector; lab operations never replace it."""
import hashlib
import json
import re
import shlex
import time
import uuid

ROLE='org.dnlab.shared-realnet.role'
CONFIG='org.dnlab.shared-realnet.config'
CREATOR='org.dnlab.shared-realnet.creator'


class ReflectorError(RuntimeError):pass


class QualificationStore:
    """Root-only atomic qualification, pinned to an immutable container ID."""
    def __init__(self,master,directory='/var/lib/dnlab/shared-realnet'):
        self.master,self.directory=master,directory

    def access(self,identity,record=None):
        if not re.fullmatch('[0-9a-f]{64}',identity):raise ReflectorError('invalid reflector container identity')
        source='''import json,os,pathlib,stat,sys,tempfile
directory=pathlib.Path(sys.argv[1]);path=directory/('rr-'+sys.argv[2]+'.json')
if directory.resolve()!=directory.absolute():raise RuntimeError('qualification directory is a symlink')
writing=len(sys.argv)>3
if writing:directory.mkdir(parents=True,exist_ok=True,mode=0o700)
if directory.exists():
 info=directory.stat()
 if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('qualification directory ownership/mode mismatch')
def read():
 try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:return None
 with os.fdopen(fd) as stream:
  info=os.fstat(stream.fileno())
  if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:raise RuntimeError('qualification ownership/mode mismatch')
  return json.load(stream)
current=read()
if writing:
 value=json.loads(sys.argv[3])
 if current is not None and current!=value:raise RuntimeError('qualification record differs')
 if current is None:
  fd,temporary=tempfile.mkstemp(dir=directory,prefix='.rr-')
  try:
   with os.fdopen(fd,'w') as stream:
    json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
   os.replace(temporary,path)
   fd=os.open(directory,os.O_DIRECTORY)
   try:os.fsync(fd)
   finally:os.close(fd)
  finally:
   if os.path.exists(temporary):os.unlink(temporary)
 current=value
print(json.dumps(current))
'''
        args=['python3','-c',source,self.directory,identity]
        if record is not None:args.append(json.dumps(record,sort_keys=True,separators=(',',':')))
        try:return json.loads(self.master.run(shlex.join(args)))
        except Exception:raise ReflectorError('reflector qualification record cannot be verified') from None

    def read(self,identity):return self.access(identity)
    def save(self,identity,record):return self.access(identity,record)


class ReflectorGuard:
    def __init__(self,master,*,name='dnlab-realnet-rr',qualifications=None):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name):raise ReflectorError('invalid reflector name')
        self.master,self.name=master,name
        self.qualifications=qualifications or QualificationStore(master)
        self.created_identity=None

    def run(self,*args):
        try:return self.master.run(shlex.join(args))
        except Exception:raise ReflectorError('reflector command failed; explicit infrastructure recovery required') from None

    def inspect(self):
        identity=self.run('docker','ps','-aq','--no-trunc','--filter','name=^/'+self.name+'$').strip()
        if not identity:return None
        if not re.fullmatch('[0-9a-f]{64}',identity):raise ReflectorError('ambiguous reflector identity')
        try:value=json.loads(self.run('docker','inspect',identity))[0]
        except (ValueError,KeyError,IndexError,TypeError):raise ReflectorError('invalid reflector inspection') from None
        if value.get('Id')!=identity or value.get('Name')!='/'+self.name:raise ReflectorError('reflector identity changed')
        return value

    def image(self,reference):
        try:value=json.loads(self.run('docker','image','inspect',reference))[0]
        except (ValueError,IndexError,TypeError):raise ReflectorError('invalid reflector image inspection') from None
        if not re.fullmatch('sha256:[0-9a-f]{64}',value.get('Id','')):raise ReflectorError('immutable reflector image required')
        return value

    def network(self,name,subnet,parent):
        try:value=json.loads(self.run('docker','network','inspect',name))[0]
        except (ValueError,IndexError,TypeError):raise ReflectorError('invalid reflector network inspection') from None
        if (not re.fullmatch('[0-9a-f]{64}',value.get('Id','')) or value.get('Name')!=name or value.get('Driver')!='macvlan'
                or value.get('Options',{}).get('parent')!=parent or value.get('Options',{}).get('macvlan_mode')!='bridge'
                or [entry.get('Subnet') for entry in value.get('IPAM',{}).get('Config',[])]!=[subnet]):
            raise ReflectorError('shared reflector network configuration differs')
        return value

    @staticmethod
    def routing_commands(configuration):
        prefixes=('router bgp ','bgp router-id ','bgp listen range ','neighbor ','route-map ',
                  'match community ','set community ','bgp community-list ','address-family ')
        return sorted({line.strip() for line in configuration.splitlines() if line.strip().startswith(prefixes)})

    def expected(self,image,network,ip,configuration):
        return {'name':self.name,'image':image['Id'],'network':network['Name'],'network_id':network['Id'],
                'ip':ip,'config_sha256':hashlib.sha256(configuration.encode()).hexdigest(),
                'routing_commands_sha256':hashlib.sha256(json.dumps(self.routing_commands(configuration)).encode()).hexdigest()}

    @staticmethod
    def fingerprint(expected):
        return hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def verify(self,container,image,expected,*,qualify=False):
        if not isinstance(container,dict) or not re.fullmatch('[0-9a-f]{64}',container.get('Id','')):
            raise ReflectorError('reflector identity cannot be verified')
        identity=container['Id'];config=container.get('Config',{});host=container.get('HostConfig',{})
        networks=container.get('NetworkSettings',{}).get('Networks',{})
        endpoint=networks.get(expected['network'],{})
        if (container.get('Image')!=expected['image'] or host.get('NetworkMode') not in (expected['network'],expected['network_id'])
                or host.get('Privileged') is not True or not any(cap in ('NET_ADMIN','CAP_NET_ADMIN') for cap in (host.get('CapAdd') or []))
                or set(networks)!={expected['network']} or endpoint.get('NetworkID')!=expected['network_id']
                or endpoint.get('IPAddress')!=expected['ip']
                or config.get('Entrypoint')!=image['Config'].get('Entrypoint') or config.get('Cmd')!=image['Config'].get('Cmd')):
            raise ReflectorError('shared reflector container configuration differs')
        labels=config.get('Labels') or {};fingerprint=self.fingerprint(expected)
        managed=labels.get(ROLE)=='route-reflector-v1' and labels.get(CONFIG)==fingerprint and re.fullmatch('[0-9a-f]{32}',labels.get(CREATOR,'') or '')
        record={'container_id':identity,'fingerprint':fingerprint,'scope':'shared-realnet-route-reflector-v1'}
        if not managed:
            if any(key in labels for key in (ROLE,CONFIG,CREATOR)):
                raise ReflectorError('reflector ownership labels differ')
            if not qualify and self.qualifications.read(identity)!=record:
                raise ReflectorError('unqualified legacy reflector; explicit qualification required')
        if container.get('State',{}).get('Running') is not True:
            raise ReflectorError('shared reflector is stopped; explicit infrastructure recovery required')
        actual=self.run('docker','exec',identity,'sha256sum','/etc/frr/frr.conf').split()
        if not actual or actual[0]!=expected['config_sha256']:raise ReflectorError('shared reflector FRR configuration differs')
        rc,output,_=self.master.run_no_check(shlex.join(['docker','exec',identity,'vtysh','-c','show bgp vrfs json']))
        try:ready=json.loads(output)
        except (ValueError,TypeError):ready=None
        if (rc!=0 or not isinstance(ready,dict) or set(ready.get('vrfs',{}))!={'default'}
                or ready['vrfs']['default'].get('routerId')!=expected['ip']):
            raise ReflectorError('shared reflector BGP daemon is not ready')
        running=self.run('docker','exec',identity,'vtysh','-c','show running-config')
        digest=hashlib.sha256(json.dumps(self.routing_commands(running)).encode()).hexdigest()
        if digest!=expected['routing_commands_sha256']:
            raise ReflectorError('shared reflector running BGP configuration differs')
        current=self.inspect()
        if not current or current['Id']!=identity or current['State'].get('Running') is not True:
            raise ReflectorError('reflector identity or state changed during verification')
        if qualify and not managed:self.qualifications.save(identity,record)
        return {'container_id':identity,'managed':bool(managed),'qualified':True}

    def create(self,image,expected):
        fingerprint=self.fingerprint(expected)
        creator=uuid.uuid4().hex
        identity=self.run('docker','run','-d','--name',self.name,'--hostname','realnet-rr','--privileged','--cap-add','NET_ADMIN',
                          '--network',expected['network'],'--ip',expected['ip'],
                          '--label',ROLE+'=route-reflector-v1','--label',CONFIG+'='+fingerprint,
                          '--label',CREATOR+'='+creator,expected['image']).strip()
        current=self.inspect()
        if (not current or current['Id']!=identity or current['Config']['Labels'].get(CONFIG)!=fingerprint
                or current['Config']['Labels'].get(CREATOR)!=creator):
            raise ReflectorError('new reflector identity cannot be verified')
        self.created_identity=(identity,creator,fingerprint)
        return identity

    def configure_new(self,identity,configuration):
        current=self.inspect()
        labels=current.get('Config',{}).get('Labels',{}) if current else {}
        if self.created_identity!=(identity,labels.get(CREATOR),labels.get(CONFIG)) or not current or current['Id']!=identity:
            raise ReflectorError('configuration requires this operation’s newly created reflector')
        # SFTP avoids putting FRR passwords in logged shell commands.
        path=self.run('mktemp','/tmp/dnlab-rr-config-XXXXXXXXXX').strip()
        if not re.fullmatch('/tmp/dnlab-rr-config-[A-Za-z0-9]{10}',path):raise ReflectorError('invalid reflector configuration tempfile')
        try:
            self.master.upload_text(configuration,path)
            self.run('docker','cp',path,identity+':/etc/frr/frr.conf')
            self.run('docker','exec',identity,'sh','-ec',
                     "sed -i 's/^bgpd=.*/bgpd=yes/' /etc/frr/daemons; chown frr:frr /etc/frr/frr.conf; /usr/lib/frr/frrinit.sh restart; vtysh -b")
        finally:self.run('rm','--',path)

    def wait_ready(self,image,expected,*,timeout=10):
        deadline=time.monotonic()+timeout
        while True:
            try:return self.verify(self.inspect(),image,expected)
            except ReflectorError as error:
                if str(error)!='shared reflector BGP daemon is not ready' or time.monotonic()>=deadline:raise
                time.sleep(.1)
