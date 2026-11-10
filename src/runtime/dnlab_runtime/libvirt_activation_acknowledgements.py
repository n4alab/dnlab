"""Durable service acknowledgements from an original qualified monitor.

A monitor reference must exist before its start command. Providers may only read
that monitor's original generation, never discover/adopt a matching current unit.
No monitor creator, process launcher, systemctl or socket reader is supplied.
"""
from copy import deepcopy
import json
import re

from .libvirt_activation import steps
from .libvirt_activation_commands import command_plan
from .libvirt_service_observer import qualify_service
from .manifest import Conflict,canonical,fingerprint


class ActivationAcknowledgements:
    def __init__(self,journal,*,binary,activation_reader,command_reader,command_intent,monitor,preflight,window,command_builder=None):
        if not all(callable(fn) for fn in (activation_reader,command_reader,command_intent,preflight)):
            raise Conflict('explicit original service acknowledgement providers required')
        self.journal,self.binary,self.window=journal,deepcopy(binary),window
        self.activation_reader,self.command_reader,self.monitor,self.preflight=activation_reader,command_reader,monitor,preflight
        self.command_intent=command_intent
        self.command_builder=command_plan if command_builder is None else command_builder
        if not callable(self.command_builder):raise Conflict('explicit acknowledgement command builder required')
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_acknowledgements '
                '(activation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(activation_id,nonce))')

    def _request(self,item,operation):
        value=self.activation_reader(operation);source=value['installation']
        matches=[current for current in value['items'] if current['spec']==item['spec'] and current['nonce']==item['nonce']]
        if (value['id']!=operation or value['installation_sha256']!=fingerprint(source)
                or len(matches)!=1 or matches[0]['phase'] not in ('requested','confirmed')
                or item['spec']['kind']!='start' or [entry['spec'] for entry in value['items']]!=steps(source['profile'])):
            raise Conflict('original requested service acknowledgement required')
        command=self.command_builder(source,item,operation,self.binary)
        request=dict(activation_id=operation,installation_sha256=fingerprint(source),context=deepcopy(source['context']),
            spec=deepcopy(item['spec']),nonce=item['nonce'],command_sha256=fingerprint(command))
        return request,source

    def _reference(self,reference,request):
        if (not isinstance(reference,dict) or set(reference)!={'kind','token','request_sha256','context_sha256'}
                or reference['kind']!='original-activation-monitor-v1'
                or not isinstance(reference['token'],str) or re.fullmatch('[0-9a-f]{32}',reference['token']) is None
                or reference['request_sha256']!=fingerprint(request) or reference['context_sha256']!=fingerprint(request['context'])):
            raise Conflict('original service monitor reference differs')
        if self.monitor.verify(deepcopy(reference),deepcopy(request)) is not True:
            raise Conflict('original service monitor lost or changed')

    def _window(self,value):
        request=value['request']
        if self.window.receipt['context']!=request['context']:raise Conflict('original service acknowledgement context differs')
        self.window.verify(dict(spec=request['spec']),request['activation_id'],value['window_sha256'])

    def _preflight(self,request,receipt,source):
        observed=self.preflight(deepcopy(request),deepcopy(receipt))
        if (not isinstance(observed,dict) or set(observed)!={'qualified','installation_sha256','context_sha256','resources_sha256'}
                or observed['qualified'] is not True or observed['installation_sha256']!=fingerprint(source)
                or observed['context_sha256']!=fingerprint(source['context'])
                or not isinstance(observed['resources_sha256'],str) or re.fullmatch('[0-9a-f]{64}',observed['resources_sha256']) is None):
            raise Conflict('complete service acknowledgement resource preflight required')
        return observed

    def _read(self,item,operation):
        request,source=self._request(item,operation)
        row=self.journal.db.execute('SELECT * FROM libvirt_activation_acknowledgements WHERE activation_id=? AND nonce=?',
            (operation,item['nonce'])).fetchone()
        if row is None:return None,source
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['request']!=request
                or value['phase'] not in ('prepared','qualification_requested','confirmed')
                or value['window_sha256']!=self.window.sha256):
            raise Conflict('original service acknowledgement journal differs')
        self._reference(value['monitor_reference'],request)
        if value['phase']!='confirmed' and (value['proof'] is not None or value['witness'] is not None):
            raise Conflict('unexpected service acknowledgement proof')
        return value,source

    def _save(self,value):
        with self.journal.transaction():
            request=value['request']
            self.journal.db.execute('UPDATE libvirt_activation_acknowledgements SET payload=?,fingerprint=? WHERE activation_id=? AND nonce=?',
                (canonical(value),fingerprint(value),request['activation_id'],request['nonce']))

    def prepare(self,item,operation,monitor_reference):
        with self.journal.execution_lock:
            request,source=self._request(item,operation);self._reference(monitor_reference,request)
            prior,_=self._read(item,operation)
            if prior is not None:
                if prior['monitor_reference']!=monitor_reference or prior['phase']!='prepared':
                    raise Conflict('original service acknowledgement already tracked; no new preparation')
                self._window(prior)
                if self._preflight(request,None,source)!=prior['preflight']:raise Conflict('service preparation preflight changed')
                return deepcopy(prior)
            if self.command_intent(deepcopy(item),operation) is not None or self.command_reader(deepcopy(item),operation) is not None:
                raise Conflict('service monitor must be registered before command intent')
            value=dict(request=request,monitor_reference=deepcopy(monitor_reference),window_sha256=self.window.sha256,
                preflight=self._preflight(request,None,source),phase='prepared',witness=None,proof=None)
            self._window(value)
            with self.journal.transaction():
                self._reference(monitor_reference,request);self._window(value)
                if self._request(item,operation)[0]!=request or self.command_intent(deepcopy(item),operation) is not None:
                    raise Conflict('service monitor registration boundary changed')
                if self._preflight(request,None,source)!=value['preflight']:raise Conflict('service preparation preflight changed')
                self.journal.db.execute('INSERT INTO libvirt_activation_acknowledgements VALUES(?,?,?,?)',
                    (operation,item['nonce'],canonical(value),fingerprint(value)))
            return deepcopy(value)

    def _witness(self,value,source,item):
        request=value['request'];command=self.command_reader(deepcopy(item),request['activation_id'])
        if (not isinstance(command,dict) or set(command)!={'sha256','exit_code','process_reference_sha256'}
                or command['sha256']!=request['command_sha256'] or type(command['exit_code']) is not int or command['exit_code']!=0
                or not isinstance(command['process_reference_sha256'],str)
                or re.fullmatch('[0-9a-f]{64}',command['process_reference_sha256']) is None):
            raise Conflict('original successful service start completion required')
        self._reference(value['monitor_reference'],request)
        witness=self.monitor.read_original(deepcopy(value['monitor_reference']),deepcopy(request))
        if (not isinstance(witness,dict) or set(witness)!={'request_sha256','monitor_sha256','service'}
                or witness['request_sha256']!=fingerprint(request) or witness['monitor_sha256']!=fingerprint(value['monitor_reference'])):
            raise Conflict('original monitored service witness required')
        service=witness['service']
        qualified=qualify_service(source,request['spec']['unit'],service['socket']['path'],service)
        receipt=dict(activation_id=request['activation_id'],nonce=request['nonce'],spec_sha256=fingerprint(request['spec']),
            identity=dict(command=deepcopy(command),service=qualified))
        return deepcopy(witness),receipt

    def original_receipt(self,item,operation):
        """Read confirmed original generation only; no recursive full preflight."""
        with self.journal.execution_lock:
            value,source=self._read(item,operation)
            if value is None or value['phase']!='confirmed':return None
            witness,receipt=self._witness(value,source,item)
            if witness!=value['witness'] or receipt!=value['proof']:raise Conflict('original acknowledged generation changed')
            return receipt

    def _confirm(self,item,operation,*,recover):
        with self.journal.execution_lock:
            value,source=self._read(item,operation)
            if value is None:raise Conflict('original service monitor intent required')
            if value['phase']=='confirmed':return self.original_receipt(item,operation)
            if recover:
                if value['phase']!='qualification_requested':raise Conflict('original requested service qualification required')
            else:
                if value['phase']!='prepared':raise Conflict('uncertain service qualification requires recovery')
                self._window(value);value['phase']='qualification_requested';self._save(value)
            self._window(value)
            witness,receipt=self._witness(value,source,item)
            if self._preflight(value['request'],receipt,source)!=value['preflight']:
                raise Conflict('service acknowledgement resource preflight changed')
            if self._witness(value,source,item)!=(witness,receipt):raise Conflict('original monitored generation changed during qualification')
            self._window(value)
            if self._request(item,operation)[0]!=value['request']:raise Conflict('original service activation source changed')
            value.update(phase='confirmed',witness=witness,proof=receipt);self._save(value)
            return self.original_receipt(item,operation)

    def qualify(self,item,operation):return self._confirm(item,operation,recover=False)
    def recover(self,item,operation):return self._confirm(item,operation,recover=True)
