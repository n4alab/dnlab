"""Local infrastructure probe birth/endpoint journal under coordinator admission.

Caller holds the original management seal and serializes host attempts. This
worker is not a scheduler. An uncertain birth is never retried as a new create.
"""
from copy import deepcopy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
import sys
from urllib.parse import quote,urlencode

try:
    BaseWorker
except NameError:
    from .jumphost_host import (Worker as BaseWorker,JumphostError,canonical,digest,
        signature,MUTATE_PROGRAM,DockerExecHTTP)
    from .management_probe_runtime import packet_program
    PACKET_SOURCE=packet_program()
    from .management_probe_exec import Execution,prepare_assets,probe_binds
    from .management_packet_receipt import validate as validate_packet_result,routing_profile as validate_routing_profile
    from .management_packet_receipt import dns_profile as validate_dns_profile

INIT="import signal,sys,time;signal.signal(signal.SIGTERM,lambda *args:sys.exit(0));time.sleep(86400)"


def validate(request):
    fields={'lab','segment','host','request_id','operation_id','image','identity','attachment','management_intent',
            'management_generation','network_id','network_nonce'}
    if not isinstance(request,dict) or set(request) not in (fields,fields|{'packet_profile'}):raise JumphostError('complete original probe request required')
    value=json.loads(canonical(request))
    for key in ('lab','segment','host'):
        if not isinstance(value[key],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',value[key]):
            raise JumphostError('invalid infrastructure probe context')
    for key in ('request_id','operation_id','management_generation','network_nonce'):
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{32}',value[key]):raise JumphostError('probe generation identity required')
    if not re.fullmatch('sha256:[0-9a-f]{64}',value['image']) or not re.fullmatch('[0-9a-f]{64}',value['network_id']):
        raise JumphostError('probe immutable image/network identity required')
    row=value['identity'];cfg=value['management_intent'];attachment=value['attachment']
    if (set(row)!={'owner','ipv4','ipv6','mac','duid','iaid'} or row['owner']!='@management-probe:'+value['segment']
            or not re.fullmatch('02(?::[0-9a-f]{2}){5}',row['mac'])
            or not re.fullmatch('00:04(?::[0-9a-f]{2}){16}',row['duid']) or not re.fullmatch('[0-9a-f]{8}',row['iaid'])
            or cfg['lab']!=value['lab'] or attachment['segment']!=value['segment']
            or cfg['network']!=attachment['network'] or cfg['bridge']!=attachment['bridge']):
        raise JumphostError('probe reservation/configuration binding differs')
    subnet=ipaddress.IPv4Network(cfg['ipv4_subnet'])
    if subnet.prefixlen>29 or row['ipv4']!=str(subnet.broadcast_address-3) or row['ipv4'] not in cfg['reserved']:
        raise JumphostError('probe must use original reserved anchor IPv4')
    if row['ipv6'] and (row['ipv6'] not in cfg['reserved'] or ipaddress.IPv6Address(row['ipv6']) not in ipaddress.IPv6Network(cfg['ipv6_subnet'])):
        raise JumphostError('dedicated probe IPv6 reservation required')
    if 'packet_profile' in value:
        profile=value['packet_profile']
        if isinstance(profile,dict) and profile.get('mode')=='dns-client':
            try:validate_dns_profile(profile,value)
            except (KeyError,ValueError,TypeError,AttributeError) as error:
                raise JumphostError('original DNS client profile required') from error
            return value
        if isinstance(profile,dict) and profile.get('mode')=='routed-pair':
            try:validate_routing_profile(profile,value)
            except (KeyError,ValueError,TypeError,AttributeError) as error:
                raise JumphostError('original routing profile required') from error
            return value
        if (not isinstance(profile,dict) or set(profile)!={'interface','client_mac','client_ip','server_mac','server_ip','dns_ip','subnet','xid','ipv6'}
                or profile['interface']!='probe0' or profile['client_mac']!=row['mac'] or profile['client_ip']!=row['ipv4']
                or profile['subnet']!=cfg['ipv4_subnet'] or profile['server_ip']!=str(ipaddress.ip_interface(attachment['ipv4']).ip)
                or not re.fullmatch('[0-9a-f]{2}(?::[0-9a-f]{2}){5}',profile['server_mac'])
                or int(profile['server_mac'][:2],16)&1 or profile['server_mac']==row['mac']
                or type(profile['xid']) is not int or not 0<profile['xid']<=0xffffffff):
            raise JumphostError('packet profile differs from original probe/network identity')
        ipaddress.IPv4Address(profile['dns_ip'])
        six=profile['ipv6']
        if bool(six)!=bool(row['ipv6']):raise JumphostError('packet IPv6 family differs')
        if six:
            if (set(six)!={'server_ip','duid','iaid','address','dns','prefix','solicit_xid','request_xid'}
                    or six['duid']!=row['duid'] or six['iaid']!=row['iaid'] or six['address']!=row['ipv6']
                    or six['dns']!=str(ipaddress.ip_interface(attachment['ipv6']).ip) or six['prefix']!=cfg['ipv6_subnet']
                    or not ipaddress.IPv6Address(six['server_ip']).is_link_local
                    or any(not re.fullmatch('[0-9a-f]{6}',six[k]) for k in ('solicit_xid','request_xid'))
                    or six['solicit_xid']==six['request_xid']):raise JumphostError('packet IPv6 profile differs')
    return value


class Worker(BaseWorker):
    def __init__(self,request,*,directory,management_directory,docker=None,process_status=None,**kwargs):
        self.request=validate(request)
        super().__init__(self.request['lab'],directory=directory,management_directory=management_directory,**kwargs)
        self.key=digest(['management-probe-v1',self.request]);self.path=self.directory/(self.key+'.json')
        self.name='dnlab-probe-'+self.key[:24];self.interface='dmp'+self.key[:12];self.docker=docker or DockerExecHTTP()
        self.process_status=process_status or (lambda pid:Path('/proc/'+str(pid)+'/status').read_text())

    @staticmethod
    def load(path):
        try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return None
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise JumphostError('probe journal ownership differs')
            return json.load(stream)

    def read(self):
        record=self.load(self.path)
        if record and (record['request']!=self.request or record['context']!=self.host_context()
                or not re.fullmatch('[0-9a-f]{32}',record['nonce'])
                or record['phase'] not in ('creating','starting','attaching','active','cleanup_pending','cleaned','recovery_required')):
            raise JumphostError('original probe journal/context differs')
        return record

    def infrastructure(self,record=None):
        config={'attachment':self.request['attachment'],'management_intent':self.request['management_intent']}
        proof=self.management_network(config)
        if (proof['origin']['generation']!=self.request['management_generation']
                or proof['network']['Id']!=self.request['network_id']
                or proof['origin']['network_nonce']!=self.request['network_nonce']):
            raise JumphostError('probe original management generation differs')
        if record and proof!=record['management']:raise JumphostError('probe management proof changed')
        return proof

    def payload(self,record):
        labels=dict(record['image'].get('Config',{}).get('Labels') or {})
        labels.update({'org.dnlab.management-probe.nonce':record['nonce'],'org.dnlab.management-probe.intent':self.key})
        host={'NetworkMode':'none','CapDrop':['ALL'],'ReadonlyRootfs':True,
            'RestartPolicy':{'Name':'no'},'Sysctls':{'net.ipv6.conf.all.disable_ipv6':'0'}}
        if record.get('packet_execution'):
            files=record['packet_execution']['files']
            host.update(CapAdd=['NET_RAW'],Binds=[files['program']['path']+':/opt/dnlab-probe.py:ro',files['output']['path']+':/run/dnlab-probe.jsonl:rw'])
            host['Sysctls']['net.ipv4.ip_unprivileged_port_start']='0'
        return {'Image':self.request['image'],'Entrypoint':['python3'],'Cmd':['-c',INIT],'User':'0:0','Labels':labels,
            'Healthcheck':{'Test':['NONE']},'HostConfig':host}

    def container(self,record,*,bind=False):
        cid=record.get('container_id');named=self.docker.call('GET','/containers/'+self.name+'/json',missing=True)
        filters=urlencode({'all':'1','filters':canonical({'label':['org.dnlab.management-probe.nonce='+record['nonce']]})})
        rows=self.docker.call('GET','/containers/json?'+filters)
        if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):raise JumphostError('invalid probe birth inventory')
        ids=[row.get('Id') for row in rows]
        if ids!=([named['Id']] if named else []):raise JumphostError('probe birth renamed or ambiguous')
        if not named:
            if cid and self.docker.call('GET','/containers/'+cid+'/json',missing=True) is not None:
                raise JumphostError('probe container renamed')
            return None
        if cid and cid!=named['Id']:raise JumphostError('probe container generation replaced')
        desired=self.payload(record);cfg=named['Config'];host=named['HostConfig']
        if (named['Name']!='/'+self.name or named['Image']!=self.request['image']
                or any(cfg.get(key)!=desired[key] for key in ('Image','Entrypoint','Cmd','User','Labels','Healthcheck'))
                or cfg.get('Env')!=record['image'].get('Config',{}).get('Env')
                or any(host.get(key)!=desired['HostConfig'][key] for key in ('NetworkMode','CapDrop','ReadonlyRootfs','Sysctls'))
                or host.get('RestartPolicy') not in ({'Name':'no'},{'Name':'no','MaximumRetryCount':0})
                or host.get('Privileged') is not False
                or host.get('CapAdd') not in ((['NET_RAW'],['CAP_NET_RAW']) if record.get('packet_execution') else (None,[]))
                or not probe_binds(host.get('Binds'),desired['HostConfig'].get('Binds',[])) or host.get('PortBindings') not in (None,{})
                or host.get('PidMode','')!='' or host.get('IpcMode')!='private'
                or set(named['NetworkSettings']['Networks'])-{'none'}):
            raise JumphostError('probe container ownership/configuration differs')
        if record.get('packet_execution'):
            expected={(row.split(':',1)[0],row.split(':')[1],row.split(':')[2]=='rw') for row in desired['HostConfig']['Binds']}
            if not isinstance(named.get('Mounts'),list) or any(not isinstance(row,dict) or type(row.get('RW')) is not bool for row in named['Mounts']):
                raise JumphostError('invalid probe execution mounts')
            actual={(row.get('Source'),row.get('Destination'),row.get('RW')) for row in named.get('Mounts',[]) if row.get('Type')=='bind'}
            if actual!=expected or len(named.get('Mounts',[]))!=len(expected):raise JumphostError('probe execution mounts differ')
            Execution(self,record).assets()
        if not cid:
            if not bind or not record.get('create_attempted'):raise JumphostError('probe birth requires explicit recovery')
            record['container_id']=named['Id'];self.save(record)
        return named

    def preflight(self,record=None):
        proof=self.infrastructure(record)
        for path in self.directory.glob('*.json'):
            other=self.load(path)
            if path!=self.path and other['request']['lab']==self.lab and other['request']['segment']==self.request['segment'] and other['phase']!='cleaned':
                raise JumphostError('another local probe attempt requires cleanup')
        if record is None:
            if self.docker.call('GET','/containers/'+self.name+'/json',missing=True) or self.find(self.interface):
                raise JumphostError('probe name or endpoint occupied')
        return proof

    def pair(self,record,fd,*,capture=False):
        host=self.find(self.interface);peer=self.find('probe0',fd)
        if host is None and peer is None:return None
        qualifying=record.get('qualifying') is True
        alias_ok=lambda value:value.get('ifalias')==record['alias'] or qualifying and value.get('ifalias') in (None,'')
        if (not host or not peer or not alias_ok(host) or not alias_ok(peer)
                or any(value.get('linkinfo',{}).get('info_kind')!='veth' for value in (host,peer))
                or host.get('address')!=record['host_mac'] or peer.get('address')!=self.request['identity']['mac']
                or host.get('link_index')!=peer.get('ifindex') or peer.get('link_index')!=host.get('ifindex')
                or host.get('master') not in (None,self.request['attachment']['bridge'],record['bridge']['ifindex'])):
            raise JumphostError('probe endpoint ownership or peer differs')
        for side,value in (('host',host),('peer',peer)):
            if record.get(side):
                actual,expected=signature(value),dict(record[side])
                if qualifying:actual.pop('ifalias');expected.pop('ifalias')
                if actual!=expected:raise JumphostError('probe endpoint generation replaced')
        if not record.get('host') and (not capture or not record.get('endpoint_attempted')):
            raise JumphostError('probe endpoint recovery proof required')
        if capture:
            record['host']=signature(host);record['peer']=signature(peer);self.save(record)
        return host

    def attach(self,record):
        self.infrastructure(record)
        with self.namespace(record,capture=True) as fd:
            host=self.pair(record,fd,capture=True)
            if host is None:
                if record.get('host') or record.get('endpoint_attempted'):raise JumphostError('original probe endpoint disappeared')
                record.update(endpoint_attempted=True,qualifying=True,step='endpoint_create');self.save(record)
                self.infrastructure(record);self.container(record)
                self.run(['ip','link','add',self.interface,'address',record['host_mac'],'alias',record['alias'],
                    'type','veth','peer','name','probe0','address',self.request['identity']['mac'],'alias',record['alias'],
                    'netns','/proc/self/fd/'+str(fd)],pass_fds=(fd,))
                self.pair(record,fd,capture=True)
            def step(side,operation,value):
                self.infrastructure(record);self.container(record);self.pair(record,fd)
                record['step']=side+'_'+operation;self.save(record)
                scope=record['context'] if side=='host' else dict(record['namespace'],boot_id=record['context']['boot_id'])
                payload={'context':scope,'link':record[side],'operation':operation,'value':value}
                prefix=['nsenter','--net=/proc/self/fd/'+str(fd)] if side=='peer' else []
                self.run(prefix+['python3','-c',MUTATE_PROGRAM,canonical(payload)],**({'pass_fds':(fd,)} if side=='peer' else {}))
                self.pair(record,fd,capture=True)
            if record.get('qualifying'):
                step('host','alias',record['alias'])
                step('peer','alias',record['alias'])
                if any(record[side]['ifalias']!=record['alias'] for side in ('host','peer')):
                    raise JumphostError('probe endpoint aliases incomplete')
                record['qualifying']=False;self.save(record)
                self.pair(record,fd)
            for side,operation,value in (('host','master',record['bridge']),('host','up',None),('peer','up',None)):
                step(side,operation,value)
            current=self.pair(record,fd)
            if current.get('master') not in (record['bridge']['ifindex'],self.request['attachment']['bridge']):raise JumphostError('probe bridge attachment incomplete')
            if 'UP' not in current.get('flags',[]) or 'UP' not in self.find('probe0',fd).get('flags',[]):raise JumphostError('probe endpoint down')

    def ensure(self,record=None):
        proof=self.preflight(record)
        if record is None:
            image=self.docker.call('GET','/images/'+quote(self.request['image'],safe='')+'/json')
            if image.get('Id')!=self.request['image'] or image.get('Config',{}).get('Volumes'):
                raise JumphostError('immutable probe image without anonymous volumes required')
            nonce=uuid.uuid4().hex
            record={'request':self.request,'context':self.host_context(),'nonce':nonce,'image':image,'management':proof,
                'bridge':signature(self.find(self.request['attachment']['bridge'])),'alias':'dnlab-management-probe:'+nonce,
                'host_mac':'02:'+':'.join(digest([self.key,nonce])[i:i+2] for i in range(0,10,2)),
                'phase':'creating','create_attempted':False}
            self.save(record)
        if record['phase']=='cleaned':
            self.verify_cleaned(record);return record
        if record['phase']=='cleanup_pending':raise JumphostError('probe cleanup must finish before reuse')
        if 'packet_profile' in self.request:prepare_assets(self,record,PACKET_SOURCE)
        container=self.container(record,bind=True)
        if container is None:
            if record.get('create_attempted'):raise JumphostError('original probe create uncertain; no new create permitted')
            record.update(create_attempted=True,step='container_create');self.save(record)
            self.infrastructure(record)
            result=self.docker.call('POST','/containers/create?'+urlencode({'name':self.name}),self.payload(record))
            if not re.fullmatch('[0-9a-f]{64}',result.get('Id','')):raise JumphostError('probe create response uncertain')
            record['container_id']=result['Id'];self.save(record);container=self.container(record)
        if not container['State']['Running']:
            if record.get('namespace') or record.get('start_attempted'):raise JumphostError('probe start uncertain or original process stopped')
            record.update(phase='starting',start_attempted=True,step='container_start');self.save(record)
            self.infrastructure(record);self.container(record)
            self.docker.call('POST','/containers/'+record['container_id']+'/start')
        record['step']='init_readiness';self.save(record)
        with self.namespace(record,capture=True):
            deadline=time.monotonic()+10
            while True:
                current=self.container(record)
                if not current or not current['State']['Running']:raise JumphostError('probe init exited before readiness')
                rows=dict(line.split(':',1) for line in self.process_status(current['State']['Pid']).splitlines() if ':' in line)
                ready=bool(int(rows.get('SigCgt','0').strip(),16)&(1<<14))
                fresh=self.container(record)
                if fresh['State']!=current['State']:raise JumphostError('probe process changed during readiness')
                if ready:break
                if time.monotonic()>=deadline:raise JumphostError('probe SIGTERM handler readiness timeout')
                time.sleep(.05)
        record['phase']='attaching';self.save(record);self.attach(record)
        record['phase']='active';self.save(record);return record

    @staticmethod
    def birth(record):
        return {key:deepcopy(record.get(key)) for key in ('container_id','nonce','namespace','started_at','host','peer')}

    def check_birth(self,record,expected_birth,*,required=False):
        pinned=record.get('coordinator_birth') if record else None
        if expected_birth is not None and (not isinstance(expected_birth,dict)
                or set(expected_birth)!=set(self.birth({})) or any(value is None for value in expected_birth.values())):
            raise JumphostError('complete expected original probe birth required')
        if required and expected_birth is None:
            raise JumphostError('expected original probe birth required')
        if (expected_birth is not None and (record is None or self.birth(record)!=expected_birth)
                or pinned is not None and (self.birth(record)!=pinned or expected_birth is not None and pinned!=expected_birth)):
            raise JumphostError('expected original probe birth differs; recovery retained')

    def inspect(self,record):
        if not record or record['phase']!='active':raise JumphostError('original active probe required for inspection')
        self.preflight(record);self.container(record)
        with self.namespace(record) as fd:self.packet_endpoint(record,fd)
        if record.get('packet_execution'):
            execution=Execution(self,record);execution.inventory()
            if execution.op['id']:execution.inspect(execution.op['id'])
        return record

    def packet_endpoint(self,record,fd):
        host=self.pair(record,fd)
        if (not host or host.get('master') not in (record['bridge']['ifindex'],self.request['attachment']['bridge'])
                or 'UP' not in host.get('flags',[]) or 'UP' not in self.find('probe0',fd).get('flags',[])):
            raise JumphostError('original active probe binding required before packets')

    def packet_process(self,current,birth):
        base=Path('/proc')/str(current['Pid'])
        status=dict(line.split(':',1) for line in (base/'status').read_text().splitlines() if ':' in line)
        ns=os.stat(base/'ns/net')
        if ((base/'stat').read_text().rsplit(')',1)[1].split()[19]!=birth['start']
                or status.get('NSpid','').split()[-1:]!=[str(birth['pid'])]
                or {'device':ns.st_dev,'inode':ns.st_ino}!=birth['namespace']):
            raise JumphostError('packet exec host process differs')

    def packets(self,record):
        if not record or record['phase']!='active' or 'packet_profile' not in self.request:
            raise JumphostError('original active probe and packet profile required')
        if not record.get('packet_execution'):
            raise JumphostError('unqualified legacy packet process requires recovery')
        return Execution(self,record).run()

    def verify_cleaned(self,record):
        if record.get('packet_execution'):
            if record['packet_execution']['start_attempted'] and not record['packet_execution']['exit_verified']:
                raise JumphostError('packet exec exit unresolved')
        elif record.get('packet_phase')=='applying':raise JumphostError('legacy packet process exit unresolved')
        if self.container(record) or self.find(self.interface):raise JumphostError('cleaned probe resources remain or were replaced')

    def cleanup(self,record):
        self.preflight(record)
        if record.get('packet_execution'):Execution(self,record).cleanup()
        elif record.get('packet_phase')=='applying':raise JumphostError('legacy packet process exit unresolved; cleanup pending')
        if record['phase']=='cleaned':self.verify_cleaned(record);return record
        value=self.container(record,bind=True)
        if value and value['State']['Running']:
            with self.namespace(record,capture=True) as fd:self.pair(record,fd,capture=True)
        host=self.find(self.interface)
        if host and (not record.get('host') or signature(host)!=record['host']):raise JumphostError('probe cleanup endpoint unqualified')
        record['phase']='cleanup_pending';self.save(record)
        if host:
            self.infrastructure(record);self.container(record)
            self.delete_link(record['host'],record['context'])
            if self.find(self.interface):raise JumphostError('probe endpoint removal incomplete')
        if value:
            if value['State']['Running']:
                self.container(record);self.docker.call('POST','/containers/'+value['Id']+'/kill?signal=SIGTERM')
                deadline=time.monotonic()+10
                while self.container(record)['State']['Running']:
                    if time.monotonic()>=deadline:raise JumphostError('probe shutdown timeout; cleanup pending')
                    time.sleep(.1)
            current=self.container(record)
            if current:self.docker.call('DELETE','/containers/'+current['Id'])
        elif record.get('create_attempted') and not record.get('container_id'):
            raise JumphostError('probe create outcome unknown; cleanup pending')
        self.verify_cleaned(record);record.update(phase='cleaned',cleanup_verified=True);self.save(record);return record

    def operate(self,action,*,expected_birth=None,expected_execution=None):
        if action not in ('preflight','ensure','inspect','prepare-packets','start-packets','cleanup','verify-cleaned','packets'):raise JumphostError('unsupported infrastructure probe action')
        if action=='preflight':self.preflight(self.read());return {'phase':'preflight','request_fingerprint':digest(self.request)}
        if action=='inspect' and not self.directory.exists():raise JumphostError('original probe journal required for inspection')
        with self.locked():
            record=self.read()
            self.check_birth(record,expected_birth,required=action in ('prepare-packets','start-packets','packets') or action=='cleanup' and bool(record and record.get('coordinator_birth')))
            execution=Execution(self,record) if record and record.get('packet_execution') else None
            if expected_execution is not None and (execution is None or execution.identity()!=expected_execution):
                raise JumphostError('expected original packet exec differs')
            if action in ('start-packets','packets') and expected_execution is None:raise JumphostError('expected original packet exec required')
            if action=='cleanup' and execution and execution.op['start_attempted'] and expected_execution is None:
                raise JumphostError('expected original packet exec required for cleanup')
            if action=='inspect':return self.inspect(record)
            if expected_birth is not None and action in ('prepare-packets','start-packets','packets','cleanup') and not record.get('coordinator_birth'):
                record['coordinator_birth']=deepcopy(expected_birth);self.save(record)
            try:
                if action=='ensure':return self.ensure(record)
                if record is None:raise JumphostError('original probe journal required for cleanup')
                if action=='verify-cleaned':
                    if record['phase']!='cleaned' or not record.get('cleanup_verified'):raise JumphostError('probe cleanup pending')
                    self.verify_cleaned(record);return record
                if action=='prepare-packets':
                    if not execution:raise JumphostError('packet exec intent missing')
                    execution.prepare();return record
                if action=='start-packets':
                    if not execution or record['phase']!='active':raise JumphostError('original active packet exec required')
                    return execution.start()
                if action=='packets':return self.packets(record)
                return self.cleanup(record)
            except Exception:
                # Existing phase/intent is authoritative. Never discard an
                # uncertain create or qualify absence from a single lookup.
                raise


def main():
    envelope=json.load(sys.stdin)
    worker=Worker(envelope['request'],**envelope['directories'])
    record=worker.operate(envelope['action'],expected_birth=envelope.get('expected_birth'),expected_execution=envelope.get('expected_execution'))
    if envelope['action']=='preflight':result=record
    else:
        result={'phase':record['phase'],'request_fingerprint':digest(worker.request),
            'cleanup_verified':record.get('cleanup_verified',False),
            'resource_proof':worker.birth(record)}
        if 'packet_result' in record:result['packet_result']=record['packet_result']
        if record.get('packet_execution'):
            result['execution']=Execution(worker,record).identity()
            result['execution_status']={k:record['packet_execution'].get(k) for k in ('phase','start_attempted','exit_verified','exit_code','error')}
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
