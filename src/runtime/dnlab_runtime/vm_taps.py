"""VM-wide TAP admission/retention, before bridge configuration or QEMU handoff.

Providers must retain the creator lease and recover its original worker receipt.
Discovery by interface name is never a creation acknowledgement. Reservations
and original receipts stay held until separately qualified full VM cleanup.
"""
from copy import deepcopy
import json
import os
import re
import stat
from xml.etree import ElementTree as ET

from .backend_reservations import available, verify_tap_reservations
from .manifest import Conflict, canonical, fingerprint
from .vm_tap_device import context as namespace, request as tap_request, IFF_TAP, IFF_NO_PI, IFF_VNET_HDR
from .vm_tap_retention import PERSIST, ownership, request_part, signature
from .vm_template import digest, fields, require


class VMTaps:
    def __init__(self, definitions, *, endpoints, read_context, preflight):
        require(all(callable(getattr(endpoints,name,None)) for name in ('observe','create','recover'))
            and callable(read_context) and callable(preflight), 'qualified original VM TAP providers required')
        self.definitions, self.journal = definitions, definitions.journal
        self.endpoints,self.read_context,self.preflight = endpoints,read_context,preflight
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_intents '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_ifindices '
                '(ifindex INTEGER PRIMARY KEY,operation_id TEXT NOT NULL,interface_name TEXT NOT NULL, '
                'UNIQUE(operation_id,interface_name))')

    def _plan(self, definition, context, requests):
        context=namespace(context)
        require(type(requests) is list and requests, 'complete original VM TAP requests required')
        requests=[tap_request(request) for request in requests]
        interfaces=ET.fromstring(definition['xml']).findall('devices/interface')
        require(len(interfaces)==len(requests), 'complete original VM NIC inventory required')
        for field in ('name','ifindex','nonce'):
            require(len({request[field] for request in requests})==len(requests), 'distinct VM TAP '+field+' required')
        profile=self.definitions.session.profile
        result=[]
        for interface,request in zip(interfaces,requests):
            target=interface.find('target')
            require(target is not None and target.attrib==dict(dev=request['name'],managed='no'),
                'original ordered unmanaged VM TAP target differs')
            result.append(dict(tap=request,context=deepcopy(context),uid=profile['uid'],gid=profile['gid'],
                interface_xml=ET.tostring(interface,encoding='unicode')))
        return result

    def read(self, operation):
        row=self.journal.db.execute('SELECT * FROM vm_tap_intents WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM TAP set missing')
        value=json.loads(row['payload']);definition=self.definitions.read(operation)
        fields(value,('id','birth','definition_sha256','context','phase','items'),'VM TAP set')
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=operation
                or value['birth']!=definition['birth'] or row['domain_uuid']!=value['birth']['uuid']
                or value['definition_sha256']!=definition['request_fingerprint']
                or value['phase'] not in ('prepared','creating','retained')):
            raise Conflict('original VM TAP set lineage differs')
        specs=self._plan(definition,value['context'],[item['spec']['tap'] for item in value['items']])
        for spec,item in zip(specs,value['items']):
            fields(item,('spec','phase','proof'),'VM TAP item')
            if item['spec']!=spec or item['phase'] not in ('prepared','create_requested','retained'):
                raise Conflict('original VM TAP item differs')
            if item['phase']=='retained':self._proof(value,item,item['proof'])
            elif item['proof'] is not None:raise Conflict('unexpected early VM TAP receipt')
        phases=[item['phase'] for item in value['items']]
        pending=[phase for phase in phases if phase!='retained']
        if (phases!=['retained']*(len(phases)-len(pending))+pending
                or pending not in (['prepared']*len(pending),['create_requested']+['prepared']*(len(pending)-1))
                or value['phase']=='retained' and pending
                or value['phase']=='prepared' and phases!=['prepared']*len(phases)):
            raise Conflict('VM TAP retention order differs')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_tap_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    @staticmethod
    def _proof(value, item, proof):
        fields(proof,('operation_id','spec_sha256','worker_reference_sha256','retention'), 'VM TAP worker receipt')
        require(proof['operation_id']==value['id'] and proof['spec_sha256']==fingerprint(item['spec'])
            and digest(proof['worker_reference_sha256']), 'original VM TAP worker receipt differs')
        retained=proof['retention'];spec=item['spec'];tap=spec['tap']
        fields(retained,('id','spec','context','lease_token','birth','uid','gid','phase','step','proof',
            'retained_proof','request_sha256'),'VM TAP retention receipt')
        require(retained['id']==tap['nonce'] and retained['spec']==tap and retained['context']==spec['context']
            and all(retained[key]==spec[key] for key in ('uid','gid'))
            and retained['phase']=='retained' and type(retained['step']) is int and retained['step']==3
            and retained['proof'] is None and retained['request_sha256']==fingerprint(request_part(retained))
            and isinstance(retained['lease_token'],str) and len(retained['lease_token'])==32
            and all(c in '0123456789abcdef' for c in retained['lease_token']), 'original VM TAP retention differs')
        birth=retained['birth'];current=retained['retained_proof']
        fields(birth,('context','request_sha256','device','flags','link'),'original TAP birth')
        device=birth['device'];link=birth['link']
        fields(device,('device','inode','mode','uid','gid','rdev'),'original TUN device')
        require(all(type(v) is int and v>=0 for v in device.values()) and device['inode']>0
            and stat.S_ISCHR(device['mode']) and (os.major(device['rdev']),os.minor(device['rdev']))==(10,200)
            and link.get('ifalias','') in ('',None) and link.get('master') in (None,0)
            and type(link.get('flags')) is list and 'UP' not in link['flags']
            and type(link.get('mtu')) is int and 68<=link['mtu']<=65535
            and isinstance(link.get('address'),str) and re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',link['address']),
            'original unconfigured TAP device receipt required')
        flags=IFF_TAP|IFF_NO_PI|(IFF_VNET_HDR if tap['vnet_header'] else 0)
        require(birth['context']==spec['context'] and birth['request_sha256']==fingerprint(tap)
            and birth['flags']==flags and birth['link']['ifindex']==tap['ifindex']
            and birth['link']['ifname']==tap['name'] and birth['link']['linkinfo']['info_kind']=='tun'
            and ownership(birth)==[-1,-1,0] and current['flags']==flags|PERSIST
            and signature(current)==signature(birth) and ownership(current)==[spec['uid'],spec['gid'],1],
            'original retained TAP kernel birth differs')
        return deepcopy(proof)

    def _bound(self, value):
        if self.read(value['id'])!=value:raise Conflict('original VM TAP intent changed')

    def _check(self, value, *, mutate, held=True):
        if held:self._bound(value)
        definition=self.definitions.read(value['id'])
        require(definition['request_fingerprint']==value['definition_sha256'], 'original VM TAP definition changed')
        self.definitions._fence(definition)
        available(self.journal,value['birth']['lab_id'],value['birth']['node_id'],'libvirt',vm_birth=value['birth'])
        self.definitions._session(definition)
        verify_tap_reservations(self.journal,value['birth'],definition['xml'])
        if mutate:
            require(definition['phase']=='prepared' and definition.get('creation_ack') is None
                and definition.get('boot') is None, 'VM TAP allocation requires original uncreated definition')
            self.definitions._absent(self.definitions.connection.lookupByUUIDString,value['birth']['uuid'])
            self.definitions._absent(self.definitions.connection.lookupByName,ET.fromstring(definition['xml']).findtext('name'))
        require(self.read_context()==value['context'], 'original VM TAP namespace changed')
        expected=dict(definition_sha256=value['definition_sha256'],session_sha256=definition['session_sha256'],
            context_sha256=fingerprint(value['context']),session_namespace_verified=True,guest_writers_absent=True)
        require(self.preflight(deepcopy(value))==expected, 'complete original VM TAP host preflight required')
        claims={(row['ifindex'],row['interface_name']) for row in self.journal.db.execute(
            'SELECT ifindex,interface_name FROM vm_tap_ifindices WHERE operation_id=?',(value['id'],))}
        wanted={(item['spec']['tap']['ifindex'],item['spec']['tap']['name']) for item in value['items']}
        if held and claims!=wanted:raise Conflict('original VM TAP ifindex reservations changed')
        for item in value['items']:
            if item['phase']=='create_requested':continue  # only original worker recovery may resolve this item
            observed=self.endpoints.observe(deepcopy(item),value['id'])
            if item['phase']=='prepared' and observed is not None:raise Conflict('VM TAP identity occupied; no adoption')
            if item['phase']=='retained' and observed!=item['proof']:
                raise Conflict('original retained VM TAP missing or replaced')
        if held:self._bound(value)
        self.definitions._fence(definition);self.definitions._session(definition)
        require(self.read_context()==value['context'], 'original VM TAP namespace changed')

    def prepare(self, operation, context, requests):
        definition=self.definitions.read(operation);specs=self._plan(definition,context,requests)
        with self.journal.execution_lock:
            if self.journal.db.execute('SELECT 1 FROM vm_tap_intents WHERE id=?',(operation,)).fetchone():
                value=self.read(operation)
                if value['context']!=context or [item['spec'] for item in value['items']]!=specs:
                    raise Conflict('original VM TAP request differs')
                return self.observe(operation)
            value=dict(id=operation,birth=deepcopy(definition['birth']),definition_sha256=definition['request_fingerprint'],
                context=namespace(context),phase='prepared',items=[dict(spec=spec,phase='prepared',proof=None) for spec in specs])
            self._check(value,mutate=True,held=False)
            with self.journal.transaction():
                self._check(value,mutate=True,held=False)
                for spec in specs:
                    if self.journal.db.execute('SELECT 1 FROM vm_tap_ifindices WHERE ifindex=?',
                            (spec['tap']['ifindex'],)).fetchone():raise Conflict('VM TAP ifindex already reserved')
                for spec in specs:
                    self.journal.db.execute('INSERT INTO vm_tap_ifindices VALUES(?,?,?)',
                        (spec['tap']['ifindex'],operation,spec['tap']['name']))
                self.journal.db.execute('INSERT INTO vm_tap_intents VALUES(?,?,?,?)',
                    (operation,value['birth']['uuid'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def observe(self, operation):
        with self.journal.execution_lock:
            value=self.read(operation);self._check(value,mutate=False)
            if any(item['phase']=='create_requested' for item in value['items']):
                raise Conflict('original VM TAP worker recovery required')
            return value

    def apply(self, operation):
        with self.journal.execution_lock:
            value=self.read(operation)
            if value['phase']=='retained':return self.observe(operation)
            for index in range(len(value['items'])):
                self._check(value,mutate=True);item=value['items'][index]
                if item['phase']=='retained':continue
                create=item['phase']=='prepared'
                if create:
                    with self.journal.transaction():
                        self._check(value,mutate=True)
                        item['phase']='create_requested';value['phase']='creating';self._save(value)
                    self._check(value,mutate=True)
                proof=(self.endpoints.create if create else self.endpoints.recover)(deepcopy(item),operation)
                proof=self._proof(value,item,proof)
                self._check(value,mutate=True)
                if self.endpoints.observe(deepcopy(item),operation)!=proof:
                    raise Conflict('original VM TAP completion not independently verified')
                with self.journal.transaction():
                    self._check(value,mutate=True)
                    item.update(phase='retained',proof=proof);self._save(value)
                    self._check(value,mutate=True)
            with self.journal.transaction():
                self._check(value,mutate=True);value['phase']='retained';self._save(value)
                self._check(value,mutate=True)
            return self.observe(operation)
