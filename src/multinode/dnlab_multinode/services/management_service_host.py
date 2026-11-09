"""Standalone composition of existing helper journals under an offline fence.

The caller owns the coordinator fence. This worker never schedules workloads or
releases that fence, and materialization does not claim DNS/DHCP packet readiness.
"""
import json
import re
import sys
from pathlib import Path
from copy import deepcopy

try:
    JumpWorker
except NameError:
    from .jumphost_host import Worker as JumpWorker, JumphostError, digest, names, AttachmentWorker, DHCPHostService, signature
    from .dns_host import Worker as DNSWorker
    from .jumphost_network_host import Worker as NetworkWorker
    from . import management_dns_probe
    DNS_PROBE_SOURCE=Path(management_dns_probe.__file__).read_text()
    from .management_routing_observation import validate as validate_routing


class Services:
    def __init__(self, intent, *, jump_directory, dns_directory, network_directory,
                 management_directory, jump=None, dns=None, network=None):
        if (not isinstance(intent,dict) or intent.get('schema_version')!=1 or intent.get('host')!='master'
                or intent.get('fingerprint')!=digest({k:v for k,v in intent.items() if k!='fingerprint'})):
            raise JumphostError('original service provisioning intent required')
        self.intent=deepcopy(intent);lab=intent['lab']
        jump_cfg=intent['jumphost'];dns_cfg=intent['dns']['config']
        if jump_cfg['lab']!=lab or dns_cfg['lab']!=lab or jump_cfg['network']!=dns_cfg['network']:
            raise JumphostError('service parent identity differs')
        external={('network' if k=='name' else k):v for k,v in jump_cfg['network'].items()}
        self.jump=jump or JumpWorker(lab,directory=jump_directory,management_directory=management_directory)
        self.dns=dns or DNSWorker(lab,directory=dns_directory)
        self.network=network or NetworkWorker(external,directory=network_directory)

    def segment_request(self, segment, record):
        return dict(request_id=digest([self.intent['fingerprint'],segment])[:32],
                    container_id=record['container_id'],generation=record['config']['generation'],
                    **deepcopy(self.intent['attachments'][segment]))

    def external_preflight(self):
        record=self.network.read();value,_=self.network.observe()
        if record:
            if value is None:
                if record.get('id'):raise JumphostError('original service external network absent')
                self.network.absent()
            else:self.network.verify(record,value)
        else:self.network.absent()
        return value

    def helper_preflight(self, worker, config, content=None):
        record=worker.read()
        image=json.loads(worker.run(['docker','image','inspect',config['image']]))
        if (len(image)!=1 or image[0].get('Id')!=config['image']
                or not re.fullmatch('sha256:[0-9a-f]{64}',config['image'])
                or image[0].get('Config',{}).get('Volumes')):
            raise JumphostError('original immutable service image unavailable')
        if record:
            if (record['config']!=config or record['action']!='ensure'
                    or record['phase'] not in ('active','creating','starting','recovery_required')
                    or record['image']!=image[0]):
                raise JumphostError('service original birth or pending operation differs')
            if content is not None:
                desired=record.get('file_operation',{}).get('content') if record.get('file_operation') else record.get('file',{}).get('content')
                if desired!=content:raise JumphostError('original DNS provisioning content differs')
            value=deepcopy(record)
            if not value.get('container_id'):
                matches=[v for v in worker.containers() if v['Names']==config['name']]
                if matches:
                    if len(matches)!=1:raise JumphostError('ambiguous pending service birth')
                    value['container_id']=matches[0]['ID']
            if value.get('container_id'):
                container=worker.container(value)
                if not container:raise JumphostError('original service container absent')
                if record['phase']=='active' and not container['State']['Running']:
                    raise JumphostError('original active service stopped')
            return value
        if any(v['Names']==config['name'] for v in worker.containers()):
            raise JumphostError('foreign service name occupied')
        return None

    def preflight(self):
        external=self.external_preflight()
        jump_cfg=self.intent['jumphost'];dns_cfg=self.intent['dns']['config']
        jump=self.helper_preflight(self.jump,jump_cfg)
        dns=self.helper_preflight(self.dns,dns_cfg,self.intent['dns']['content'])
        if jump is None:self.jump.preflight_new(jump_cfg)
        else:
            if jump.get('dhcp_structural_operation') or jump.get('inventory_operation'):
                raise JumphostError('unrelated service recovery pending')
            self.jump.infrastructure(jump)
            if jump['phase']=='active':
                with self.jump.namespace(jump) as fd:self.jump.verify_attachment(jump,fd)
        management={}
        rows=self.jump.extension_rows(jump) if jump else {}
        for segment,row in self.intent['attachments'].items():
            config=dict(jump_cfg,**row)
            proof=self.jump.management_network(config)
            management[segment]=proof['network']['Id']
            if segment=='default':continue
            if segment in rows:
                if rows[segment]['request']!=self.segment_request(segment,jump):
                    raise JumphostError('original additional service attachment differs')
                if rows[segment]['phase']=='active':
                    worker=AttachmentWorker(self.jump,jump,rows[segment])
                    worker.infrastructure(rows[segment])
                    with worker.namespace(rows[segment]) as fd:worker.verify_attachment(rows[segment],fd)
            elif self.jump.find(names(self.intent['lab'],segment)) is not None:
                raise JumphostError('additional service endpoint occupied')
        if set(rows)-set(self.intent['attachments']):raise JumphostError('unplanned service attachment exists')
        if external is not None:
            for config,record in ((jump_cfg,jump),(dns_cfg,dns)):
                for cid,endpoint in external['Containers'].items():
                    if endpoint['IPv4Address'].split('/')[0]==config['ip'] and cid!=(record or {}).get('container_id'):
                        raise JumphostError('external service IP reserved by another container')
        return {'phase':'preflight','intent_fingerprint':self.intent['fingerprint'],
                'external_network_id':external['Id'] if external else None,'management_networks':management}

    def apply(self):
        self.preflight()
        network_record=self.network.read()
        network=self.network.operate('recover' if network_record and network_record['phase']!='active' else 'ensure')
        def ensure(worker, config, content=None):
            record=worker.read()
            action='recover' if record and record['phase']!='active' else 'ensure'
            if worker is self.jump and record and any(row['phase']!='active' for row in self.jump.extension_rows(record).values()):
                action='recover'
            if worker is self.dns:return worker.operate(action,config,content)
            return worker.operate(action,config)
        dns=ensure(self.dns,self.intent['dns']['config'],self.intent['dns']['content'])
        jump=ensure(self.jump,self.intent['jumphost'])
        for segment in sorted(self.intent['attachments']):
            if segment=='default':continue
            previous=jump.get('management_attachments',{}).get(segment)
            action='segment-recover' if previous and previous['phase']!='active' else 'segment-add'
            jump=self.jump.operate(action,self.segment_request(segment,jump))
        self.preflight()
        if jump['phase']!='active' or dns['phase']!='active':raise JumphostError('service materialization incomplete')
        return {'phase':'materialized','intent_fingerprint':self.intent['fingerprint'],
                'external_network_id':network['network_id'],
                'jumphost':{k:jump[k] for k in ('container_id','nonce')},
                'dns':{k:dns[k] for k in ('container_id','nonce')},'functional_readiness_verified':False}

    def observe(self):
        """Requalify materialized resources without allocating or recovering.

        This snapshot is a prerequisite for functional probes, not permission
        to release a fence. Incomplete births and attachments remain pending.
        """
        network=self.network.read();jump=self.jump.read();dns=self.dns.read()
        if any(not row or row.get('phase')!='active' for row in (network,jump,dns)):
            raise JumphostError('complete active service journals required for observation')
        if (any(jump.get(key) for key in ('dhcp_operation','dhcp_structure',
                'dhcp_structural_operation','inventory_operation')) or dns.get('file_operation')):
            raise JumphostError('service recovery pending before observation')
        rows=self.jump.extension_rows(jump)
        if set(rows)!=set(self.intent['attachments'])-{'default'} or any(row['phase']!='active' for row in rows.values()):
            raise JumphostError('complete active service attachments required for observation')
        observed=self.preflight()
        self.dns.infrastructure(dns)
        self.jump.verify_extensions(jump)
        # preflight can recognize an unbound birth for recovery; observation
        # requires the identities already committed by the birth journals.
        for worker,record in ((self.jump,jump),(self.dns,dns)):
            if not re.fullmatch('[0-9a-f]{64}',record.get('container_id','')):
                raise JumphostError('committed service birth required for observation')
            value=worker.container(record)
            if not value or value['State']['Running'] is not True:
                raise JumphostError('original active service unavailable')
        # Do not return a mixed journal generation if another helper operation
        # committed while the kernel and Docker resources were observed.
        if network!=self.network.read() or jump!=self.jump.read() or dns!=self.dns.read():
            raise JumphostError('service journals changed during observation')
        return {'phase':'observed','intent_fingerprint':self.intent['fingerprint'],
                'external_network_id':observed['external_network_id'],
                'management_networks':observed['management_networks'],
                'jumphost':{k:jump[k] for k in ('container_id','nonce')},
                'dns':{k:dns[k] for k in ('container_id','nonce')},
                'functional_readiness_verified':False,'mutations_performed':False}

    def packet_profiles(self):
        """Read original server L2/link-local identities for bounded probes."""
        before=self.probe();jump=self.jump.read();servers={}
        with self.jump.namespace(jump) as fd:
            addresses=json.loads(self.jump.run(['nsenter','--net=/proc/self/fd/'+str(fd),'ip','-j','addr','show'],pass_fds=(fd,)))
            for segment in self.intent.get('packet_probe_identities',{}):
                config=self.intent['attachments'][segment]['attachment']
                record=jump if segment=='default' else jump['management_attachments'][segment]
                peer=self.jump.find(config['interface'],fd)
                if not peer or signature(peer)!=record['peer']:raise JumphostError('original DHCP server endpoint changed')
                local=None
                if config['ipv6']:
                    values=[v['local'] for row in addresses if row['ifname']==config['interface']
                        for v in row.get('addr_info',[]) if v.get('family')=='inet6' and v.get('scope')=='link'
                        and not set(v.get('flags',[]))&{'tentative','dadfailed'}]
                    if len(values)!=1:raise JumphostError('original DHCP server link-local missing or ambiguous')
                    local=values[0]
                servers[segment]={'mac':record['peer']['address'],'link_local':local}
        after=self.probe()
        if before!=after:raise JumphostError('service generation or process changed during packet profile observation')
        return {'phase':'packet-profiles','intent_fingerprint':self.intent['fingerprint'],
                'observation':before,'servers':servers,'service_mutations_performed':False}

    def routing_snapshot(self):
        """Observe prerequisites on the original router; retain rejected evidence.

        A successful snapshot is not a forwarding or access probe. In particular
        firewall dumps are retained for diagnosis, not certified by this action.
        """
        before=self.observe();jump=self.jump.read()
        raw={'forwarding':{},'routes':{},'rules':{},'firewall':{}}
        with self.jump.namespace(jump) as fd:
            def read(argv):
                return self.jump.run(['nsenter','--net=/proc/self/fd/'+str(fd),*argv],pass_fds=(fd,))
            for version,key,name in ((4,'ipv4','net.ipv4.ip_forward'),(6,'ipv6','net.ipv6.conf.all.forwarding')):
                raw['forwarding'][key]=read(['sysctl','-n',name]).strip()
                raw['routes'][str(version)]=json.loads(read(['ip','-j','-'+str(version),'route','show','table','main']))
                raw['rules'][str(version)]=json.loads(read(['ip','-j','-'+str(version),'rule','show']))
            for tool in ('iptables-save','ip6tables-save'):
                raw['firewall'][tool]=read([tool])
        if self.observe()!=before:raise JumphostError('service generation changed during routing observation')
        try:
            config=jump['config']
            result=validate_routing({key:row['attachment'] for key,row in self.intent['attachments'].items()},
                dict(config['network'],ip=config['ip']),raw['forwarding'],raw['routes'],raw['rules'])
            validation={'status':'accepted','result':result}
        except (ValueError,TypeError,KeyError) as error:
            validation={'status':'rejected','reason':str(error)}
        return {'phase':'routing-snapshot','intent_fingerprint':self.intent['fingerprint'],
                'observation':before,'snapshot':raw,'validation':validation,
                'functional_readiness_verified':False,'service_mutations_performed':False}

    def probe(self):
        """Probe DNS packets and qualified DHCP listeners, retaining the fence.

        DHCP packet/RA and access/routing qualification remain separate. No
        reload, daemon launch or reservation change is performed by this action.
        """
        before=self.observe();jump=self.jump.read()
        request=self.intent.get('dns_probe')
        if (not isinstance(request,dict) or set(request)!={'server','records'}
                or request['server']!=self.intent['dns']['config']['ip']
                or not isinstance(request['records'],list) or not 1<=len(request['records'])<=2):
            raise JumphostError('original bounded DNS probe intent required')
        hosts={}
        for line in self.intent['dns']['content'].splitlines():
            parts=line.split('#',1)[0].split()
            if not parts:continue
            if len(parts)!=2:raise JumphostError('original DNS hosts data differs')
            hosts.setdefault(parts[1],set()).add(parts[0])
        expected=[]
        import ipaddress
        for row in request['records']:
            if (not isinstance(row,dict) or set(row)!={'name','address'}
                    or row['address'] not in hosts.get(row['name'],set())):
                raise JumphostError('DNS probe record not bound to original hosts')
            family='A' if ipaddress.ip_address(row['address']).version==4 else 'AAAA'
            for transport in ('udp','tcp'):expected.append(dict(row,type=family,transport=transport))
        with self.jump.namespace(jump) as fd:
            raw=self.jump.run(['nsenter','--net=/proc/self/fd/'+str(fd),sys.executable,'-c',DNS_PROBE_SOURCE],
                pass_fds=(fd,),input=json.dumps(request))
        result=json.loads(raw)
        if result!={'level':'dns-packets','server':request['server'],'answers':expected}:
            raise JumphostError('DNS packet evidence differs from original probe')
        dhcp={'level':'disabled','packet_readiness_verified':False}
        if jump['config']['dhcp']:
            with self.jump.namespace(jump) as fd:
                with DHCPHostService(self.jump,jump,fd) as service:
                    observed=service.observe(jump.get('dhcp_expected_service'))
                    dhcp=service.readiness(observed)
        if self.observe()!=before:raise JumphostError('service generation changed during functional probes')
        return {'phase':'probed','intent_fingerprint':self.intent['fingerprint'],
                'observation':before,'dns':result,'dhcp':dhcp,
                'functional_readiness_verified':False,'service_mutations_performed':False}


def main():
    request=json.load(sys.stdin)
    worker=Services(request['intent'],**request['directories'])
    if request['action'] not in ('preflight','apply','observe','probe','packet_profiles','routing_snapshot'):raise JumphostError('unsupported service composition action')
    print(json.dumps(getattr(worker,request['action'])(),sort_keys=True))


if __name__=='__main__':main()
