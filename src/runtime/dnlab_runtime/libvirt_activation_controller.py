"""Compose original activation intent, commands and monitored service receipts.

Every native provider remains explicit. This controller creates no monitors and
has no default systemctl, process/socket or libvirt transport. Recovery reconciles
only already requested commands; advancing later prepared steps is explicit apply.
"""
from copy import deepcopy
import json

from .libvirt_activation import SessionActivation,steps
from .libvirt_activation_acknowledgements import ActivationAcknowledgements
from .libvirt_activation_commands import ActivationCommands,command_plan
from .libvirt_activation_services import ActivationServices
from .libvirt_package_policy import prerequisites_for_policy
from .manifest import Conflict,canonical,fingerprint,identifier


def resource_digest(source):
    policy=source.get('postboot',{}).get('package_policy')
    prerequisites=prerequisites_for_policy(source['prerequisites'],policy);prerequisites.pop('services',None)
    return fingerprint(dict(items=source['items'],prerequisites=prerequisites))


class ActivationController:
    def __init__(self,journal,installation,*,operation,window,binary,runner,source_reader,monitor,resources,inventory,empty,command_builder=None):
        identifier(operation,'original controller activation_id')
        if not all(callable(fn) for fn in (source_reader,resources,inventory,empty)):
            raise Conflict('complete explicit activation providers required')
        self.journal,self.source,self.operation,self.window=journal,deepcopy(installation),operation,window
        self.source_reader,self.monitor,self.resources,self.inventory,self.empty=source_reader,monitor,resources,inventory,empty
        self.command_builder=command_plan if command_builder is None else command_builder
        if not callable(self.command_builder):raise Conflict('explicit controller command builder required')
        expected=[spec['key'] for spec in steps(installation['profile'])]
        if (window.receipt['operation_id']!=operation or window.receipt['context']!=installation['context']
                or window.receipt['targets']!=expected):raise Conflict('separate original activation window required')
        self.binary=deepcopy(binary);self._source()
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_monitor_bindings '
                '(activation_id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        self.driver=SessionActivation(journal,self)
        self.commands=ActivationCommands(journal,binary=binary,runner=runner,activation_reader=self.driver.read,
            preflight=self._command_preflight,after_outcome=self._after_outcome,command_builder=self.command_builder)
        self.acknowledgements=ActivationAcknowledgements(journal,binary=binary,activation_reader=self.driver.read,
            command_reader=self.commands.original_completion,command_intent=self.commands._read,
            monitor=monitor,preflight=self._acknowledgement_preflight,window=window,command_builder=self.command_builder)
        self.services=ActivationServices(self.source,generation_observer=self._generation_observer)

    def _source(self):
        if self.source_reader()!=self.source:raise Conflict('original controller source changed')

    def _bound(self,value):
        self._source()
        if (value['id']!=self.operation or value['installation']!=self.source
                or value['installation_sha256']!=fingerprint(self.source)
                or [item['spec'] for item in value['items']]!=steps(self.source['profile'])):
            raise Conflict('original controller activation differs')

    def monitor_request(self,value,item):
        self._bound(value)
        command=self.command_builder(self.source,item,self.operation,self.binary)
        return dict(activation_id=self.operation,installation_sha256=fingerprint(self.source),context=deepcopy(self.source['context']),
            spec=deepcopy(item['spec']),nonce=item['nonce'],command_sha256=fingerprint(command))

    def _monitors(self,value):
        self._bound(value)
        row=self.journal.db.execute('SELECT * FROM libvirt_activation_monitor_bindings WHERE activation_id=?',(self.operation,)).fetchone()
        if row is None:raise Conflict('original activation monitor binding required')
        saved=json.loads(row['payload'])
        expected=set(item['spec']['unit'] for item in value['items'] if item['spec']['kind']=='start')
        if (fingerprint(saved)!=row['fingerprint'] or saved['activation_id']!=self.operation
                or saved['installation_sha256']!=fingerprint(self.source) or saved['window_sha256']!=self.window.sha256
                or set(saved['references'])!=expected):raise Conflict('original activation monitor binding differs')
        for item in value['items']:
            if item['spec']['kind']=='start':
                self.acknowledgements._reference(saved['references'][item['spec']['unit']],self.monitor_request(value,item))
        return deepcopy(saved['references'])

    def bind_monitors(self,references,*,after_reload=False):
        with self.journal.execution_lock:
            value=self.driver.read(self.operation);self._bound(value)
            if after_reload:
                if (any(item['phase']!='prepared' for item in value['items'][1:])
                        or self.commands.original_completion(value['items'][0],self.operation) is None):
                    raise Conflict('original reload and unrequested starts required for monitor recovery')
            elif any(item['phase']!='prepared' for item in value['items']):
                raise Conflict('monitors bind before activation actions only')
            expected={item['spec']['unit'] for item in value['items'] if item['spec']['kind']=='start'}
            if not isinstance(references,dict) or set(references)!=expected:raise Conflict('complete original monitor references required')
            saved=dict(activation_id=self.operation,installation_sha256=fingerprint(self.source),window_sha256=self.window.sha256,
                references=deepcopy(references))
            for item in value['items']:
                self._window(item)
                if item['spec']['kind']=='start':self.acknowledgements._reference(references[item['spec']['unit']],self.monitor_request(value,item))
            self.observe(value)
            with self.journal.transaction():
                self._bound(value)
                for item in value['items']:
                    self._window(item)
                    if item['spec']['kind']=='start':
                        self.acknowledgements._reference(references[item['spec']['unit']],self.monitor_request(value,item))
                self.observe(value)
                prior=self.journal.db.execute('SELECT payload,fingerprint FROM libvirt_activation_monitor_bindings WHERE activation_id=?',
                    (self.operation,)).fetchone()
                if prior:
                    if prior['payload']!=canonical(saved) or prior['fingerprint']!=fingerprint(saved):
                        raise Conflict('original activation monitors cannot be replaced')
                else:self.journal.db.execute('INSERT INTO libvirt_activation_monitor_bindings VALUES(?,?,?)',
                    (self.operation,canonical(saved),fingerprint(saved)))
            return self._monitors(value)

    def _window(self,item):
        self._source();self.window.verify(item,self.operation,self.window.sha256)

    def _receipts(self,value):
        result={}
        for item in value['items']:
            proof=None
            if item['phase']!='prepared':
                if item['spec']['kind']=='reload':
                    command=self.commands.original_completion(item,self.operation)
                    if command is not None:proof=dict(activation_id=self.operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
                        identity=dict(command=command,configuration_sha256=fingerprint(self.source['profile']['files'])))
                else:proof=self.acknowledgements.original_receipt(item,self.operation)
            result[item['spec']['key']]=proof
        return result

    def _generation_observer(self,value,item,receipt):
        references=self._monitors(value);request=self.monitor_request(value,item)
        bound=dict(request=request,monitor_reference=references[item['spec']['unit']])
        def read():
            _,current=self.acknowledgements._witness(bound,self.source,item)
            if current!=receipt:raise Conflict('original activation monitored receipt differs')
            return deepcopy(current['identity']['service'])
        return read

    def _full(self,value,receipts):
        self._bound(value)
        before=self.services.validate(value,self.inventory(),receipts)
        expected=dict(qualified=True,installation_sha256=fingerprint(self.source),context_sha256=fingerprint(self.source['context']),
            resources_sha256=resource_digest(self.source))
        if self.resources(deepcopy(value),deepcopy(receipts))!=expected:
            raise Conflict('complete controller resource preflight differs')
        if self.services.validate(value,self.inventory(),receipts)!=before:raise Conflict('controller service inventory changed')
        self._source();return expected

    def observe(self,value):
        self._bound(value);receipts=self._receipts(value);self._full(value,receipts)
        return dict(context=deepcopy(self.source['context']),installation_sha256=fingerprint(self.source),steps=receipts)

    def _command_preflight(self,command):
        value=self.driver.read(self.operation);self._monitors(value)
        matches=[item for item in value['items'] if self.command_builder(self.source,item,self.operation,self.binary)==command]
        if len(matches)!=1:raise Conflict('original controller command differs')
        item=matches[0];self._window(item)
        if item['spec']['kind']=='start':
            intent,_=self.acknowledgements._read(item,self.operation)
            if intent is None:raise Conflict('original service monitor intent required before command')
        proof=self._full(value,self._receipts(value))
        return dict(qualified=True,command_sha256=fingerprint(command),installation_sha256=proof['installation_sha256'],
            context_sha256=proof['context_sha256'],inputs_sha256=proof['resources_sha256'])

    def _acknowledgement_preflight(self,request,receipt):
        value=self.driver.read(self.operation);receipts=self._receipts(value)
        if receipt is not None:receipts[request['spec']['key']]=deepcopy(receipt)
        return self._full(value,receipts)

    def _after_outcome(self,item,operation,command_proof):
        if operation!=self.operation:raise Conflict('original controller outcome operation differs')
        if item['spec']['kind']=='reload':return
        saved,_=self.acknowledgements._read(item,operation)
        if saved is None:raise Conflict('original service monitor intent missing')
        if saved['phase']=='prepared':receipt=self.acknowledgements.qualify(item,operation)
        elif saved['phase']=='qualification_requested':receipt=self.acknowledgements.recover(item,operation)
        else:receipt=self.acknowledgements.original_receipt(item,operation)
        if receipt['identity']['command']!=command_proof:raise Conflict('original service command proof differs')

    def apply(self,item,operation):
        if operation!=self.operation:raise Conflict('original controller apply operation differs')
        value=self.driver.read(operation);references=self._monitors(value);self._window(item)
        if item['spec']['kind']=='start':self.acknowledgements.prepare(item,operation,references[item['spec']['unit']])
        self.commands.execute(item,operation)
        receipt=self._receipts(self.driver.read(operation))[item['spec']['key']]
        if receipt is None:raise Conflict('original service acknowledgement pending')
        return receipt

    def qualify_empty(self,value):
        self._bound(value);receipts=self._receipts(value);self._full(value,receipts)
        proof=self.empty(deepcopy(value),deepcopy(receipts))
        self._full(value,receipts);return proof

    def prepare(self):return self.driver.prepare(self.operation,self.source)

    def prepare_successor(self,predecessor_id,*,state_admission=None):
        return self.driver.prepare_successor(self.operation,self.source,predecessor_id=predecessor_id,
            state_admission=state_admission)

    def _reference(self,reference):
        value=self.driver.read(self.operation);self._bound(value)
        if (reference.get('id')!=self.operation or reference.get('phase')!='prepared'
                or reference.get('installation')!=self.source or reference.get('installation_sha256')!=fingerprint(self.source)
                or [(item['spec'],item['nonce']) for item in reference['items']]!=[(item['spec'],item['nonce']) for item in value['items']]):
            raise Conflict('original prepared controller reference required')
        return value

    def apply_original(self,reference):
        with self.journal.execution_lock:
            value=self._reference(reference);self._monitors(value)
            if any(item['phase']!='confirmed' for item in value['items']):
                for item in value['items']:self._window(item)
            return self.driver.apply(self.operation)

    def recover_original(self,reference):
        with self.journal.execution_lock:
            value=self._reference(reference);self._monitors(value)
            for item in value['items']:
                if item['phase']=='requested':self.commands.recover(item,self.operation)
            # No new command or later prepared step is executed by recovery.
            return self.driver.read(self.operation)
