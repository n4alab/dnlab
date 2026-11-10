"""Original systemd event-stream state machine; no native connection or launcher.

The explicit transport must subscribe before command intent, retain a pinned
manager connection and provide an ordered, loss-detecting stream. Correlation
must prove the original command's job, not merely match a unit name. Native D-Bus
subscription, job correlation and pinned process/socket reads remain to qualify.
"""
from copy import deepcopy
import json
import re
import uuid

from .libvirt_activation import steps
from .libvirt_activation_commands import command_plan
from .libvirt_service_observer import qualify_service
from .manifest import Conflict,canonical,fingerprint


def require(condition,message):
    if not condition:raise Conflict(message)


class ActivationEventMonitor:
    def __init__(self,journal,*,binary,activation_reader,command_intent,command_reader,stream,processes,correlate,observe,command_builder=None):
        require(all(callable(fn) for fn in (activation_reader,command_intent,command_reader,correlate,observe)),
            'explicit original event monitor providers required')
        self.journal,self.binary,self.stream=journal,deepcopy(binary),stream
        self.processes=processes
        self.command_builder=command_plan if command_builder is None else command_builder
        require(callable(self.command_builder),'explicit event command builder required')
        self.activation_reader,self.command_intent,self.command_reader=activation_reader,command_intent,command_reader
        self.correlate,self.observe=correlate,observe
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_event_monitors '
                '(activation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(activation_id,nonce))')

    def _bind(self,request):
        value=self.activation_reader(request['activation_id']);source=value['installation']
        matches=[i for i in value['items'] if i['nonce']==request['nonce'] and i['spec']==request['spec']]
        require(value['id']==request['activation_id'] and value['installation_sha256']==fingerprint(source)
            and [i['spec'] for i in value['items']]==steps(source['profile']) and len(matches)==1
            and matches[0]['spec']['kind']=='start','original event monitor activation differs')
        item=matches[0]
        expected=dict(activation_id=value['id'],installation_sha256=fingerprint(source),context=deepcopy(source['context']),
            spec=deepcopy(item['spec']),nonce=item['nonce'],command_sha256=fingerprint(self.command_builder(source,item,value['id'],self.binary)))
        require(request==expected,'original event monitor request differs')
        return source,item

    def _subscription(self,subscription,request):
        require(isinstance(subscription,dict) and set(subscription)=={'token','request_sha256','context_sha256','manager_owner','barrier'}
            and isinstance(subscription['token'],str) and re.fullmatch('[0-9a-f]{32}',subscription['token']) is not None
            and subscription['request_sha256']==fingerprint(request)
            and subscription['context_sha256']==fingerprint(request['context'])
            and isinstance(subscription['manager_owner'],str) and re.fullmatch(r':[0-9]+\.[0-9]+',subscription['manager_owner']) is not None
            and type(subscription['barrier']) is int and subscription['barrier']>=0,'qualified original event subscription required')
        require(self.stream.verify(deepcopy(subscription),deepcopy(request)) is True,'original event stream lost or replaced')

    def _save(self,value):
        request=value['request']
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_activation_event_monitors SET payload=?,fingerprint=? WHERE activation_id=? AND nonce=?',
                (canonical(value),fingerprint(value),request['activation_id'],request['nonce']))

    def _read(self,reference,request):
        source,item=self._bind(request)
        row=self.journal.db.execute('SELECT * FROM libvirt_activation_event_monitors WHERE activation_id=? AND nonce=?',
            (request['activation_id'],request['nonce'])).fetchone()
        require(row is not None,'original event monitor missing')
        value=json.loads(row['payload'])
        require(fingerprint(value)==row['fingerprint'] and value['request']==request and value['reference']==reference
            and reference==dict(kind='original-activation-monitor-v1',token=reference['token'],request_sha256=fingerprint(request),
                context_sha256=fingerprint(request['context'])),'original event monitor journal or reference differs')
        self._subscription(value['subscription'],request)
        return value,source,item

    def register(self,request,subscription):
        """Bind an already qualified subscription; never create/reopen one."""
        with self.journal.execution_lock:
            source,item=self._bind(request);self._subscription(subscription,request)
            prior=self.journal.db.execute('SELECT payload FROM libvirt_activation_event_monitors WHERE activation_id=? AND nonce=?',
                (request['activation_id'],request['nonce'])).fetchone()
            if prior:
                value=json.loads(prior['payload']);self._read(value['reference'],request)
                require(value['subscription']==subscription,'original event subscription cannot be replaced')
                return deepcopy(value['reference'])
            require(item['phase'] in ('prepared','requested') and self.command_intent(deepcopy(item),request['activation_id']) is None
                and self.command_reader(deepcopy(item),request['activation_id']) is None,'subscribe before original command intent')
            reference=dict(kind='original-activation-monitor-v1',token=uuid.uuid4().hex,request_sha256=fingerprint(request),
                context_sha256=fingerprint(request['context']))
            value=dict(request=deepcopy(request),subscription=deepcopy(subscription),reference=reference,
                cursor=subscription['barrier'],job=None,invocation=None,completed=False,proof=None,phase='tracking',failure=None)
            with self.journal.transaction():
                self._subscription(subscription,request)
                current_source,current_item=self._bind(request)
                require(current_source==source and current_item==item
                    and self.command_intent(deepcopy(item),request['activation_id']) is None
                    and self.command_reader(deepcopy(item),request['activation_id']) is None,'event registration boundary changed')
                self.journal.db.execute('INSERT INTO libvirt_activation_event_monitors VALUES(?,?,?,?)',
                    (request['activation_id'],request['nonce'],canonical(value),fingerprint(value)))
            return deepcopy(reference)

    def verify(self,reference,request):
        with self.journal.execution_lock:
            value,_,_=self._read(reference,request)
            require(value['phase']!='pending','original event monitor pending: '+str(value['failure']))
            return True

    def _process(self,value):
        invocation=value['invocation'];request=value['request']
        reference=invocation['process_reference']
        require(isinstance(reference,dict) and set(reference)=={'kind','token','request_sha256','subscription_sha256',
                'invocation_id','pid','start_ticks','boot_id','namespaces_sha256'}
            and reference['kind']=='original-service-process-v1'
            and isinstance(reference['token'],str) and re.fullmatch('[0-9a-f]{32}',reference['token']) is not None
            and reference['request_sha256']==fingerprint(request)
            and reference['subscription_sha256']==fingerprint(value['subscription'])
            and reference['invocation_id']==invocation['invocation_id'] and reference['pid']==invocation['pid']
            and type(reference['pid']) is int and reference['pid']>0
            and type(reference['start_ticks']) is int and reference['start_ticks']>0
            and reference['boot_id']==request['context']['boot_id']
            and reference['namespaces_sha256']==fingerprint(request['context']['namespaces']),
            'original event process reference required')
        require(self.processes.verify(deepcopy(reference),deepcopy(request),deepcopy(value['subscription'])) is True,
            'original event process or pidfd lost or replaced')
        return reference

    def _batch(self,value):
        batch=self.stream.read(deepcopy(value['subscription']),after=value['cursor'],limit=256)
        require(isinstance(batch,dict) and set(batch)=={'subscription_sha256','after','through','continuous','events'}
            and batch['subscription_sha256']==fingerprint(value['subscription'])
            and type(batch['after']) is int and batch['after']==value['cursor']
            and type(batch['through']) is int and batch['continuous'] is True
            and isinstance(batch['events'],list) and len(batch['events'])<=256
            and batch['through']==value['cursor']+len(batch['events']),'event continuity missing or ambiguous')
        for sequence,event in enumerate(batch['events'],value['cursor']+1):
            require(isinstance(event,dict) and type(event.get('sequence')) is int and event['sequence']==sequence
                and event.get('unit')==value['request']['spec']['unit'],'event sequence or unit differs')
            kind=event.get('kind');common={'sequence','kind','unit'}
            if kind=='job-new':
                require(set(event)==common|{'job_path'} and value['job'] is None
                    and isinstance(event['job_path'],str) and re.fullmatch('/org/freedesktop/systemd1/job/[1-9][0-9]*',event['job_path']) is not None,
                    'duplicate or ambiguous original start job')
                require(self.correlate(deepcopy(value['request']),deepcopy(value['subscription']),deepcopy(event)) is True,
                    'event job not correlated with original command')
                value['job']=event['job_path']
            elif kind=='invocation':
                require(set(event)==common|{'invocation_id','pid','process_reference'} and value['job'] is not None and value['invocation'] is None
                    and isinstance(event['invocation_id'],str) and re.fullmatch('[0-9a-f]{32}',event['invocation_id']) is not None
                    and event['invocation_id']!='0'*32 and type(event['pid']) is int and event['pid']>0,
                    'missing or replaced first service invocation')
                value['invocation']={key:deepcopy(event[key]) for key in ('invocation_id','pid','process_reference')}
                self._process(value)
            elif kind=='job-removed':
                require(set(event)==common|{'job_path','result'} and value['job'] is not None
                    and event['job_path']==value['job'] and event['result']=='done' and not value['completed'],
                    'original start job failed, replaced or ambiguous')
                value['completed']=True
            else:raise Conflict('unexpected event in original service stream')
        value['cursor']=batch['through']

    def read_original(self,reference,request):
        with self.journal.execution_lock:
            value,source,item=self._read(reference,request)
            require(value['phase']!='pending','original event monitor pending: '+str(value['failure']))
            before=deepcopy(value)
            try:
                self._batch(value);self._subscription(value['subscription'],request)
                if value['invocation'] is not None:self._process(value)
                # Save the first invocation even if the original command or socket is not ready yet.
                if value!=before:self._save(value)
            except Conflict as error:
                value=before;value.update(phase='pending',failure=str(error));self._save(value)
                raise
            require(value['completed'] and value['invocation'] is not None,'original service event evidence pending')
            command=self.command_reader(deepcopy(item),request['activation_id'])
            require(isinstance(command,dict) and set(command)=={'sha256','exit_code','process_reference_sha256'}
                and command['sha256']==request['command_sha256'] and type(command['exit_code']) is int and command['exit_code']==0
                and isinstance(command['process_reference_sha256'],str) and re.fullmatch('[0-9a-f]{64}',command['process_reference_sha256']) is not None,
                'original successful command completion required for events')
            def observed():
                original=self._process(value)
                row=self.observe(deepcopy(request),deepcopy(value['invocation']))
                qualified=qualify_service(source,request['spec']['unit'],row['socket']['path'],row)
                require(all(qualified['unit'][key]==value['invocation'][key] for key in ('invocation_id','pid'))
                    and qualified['process']['start_ticks']==original['start_ticks'],
                    'observed generation differs from first event')
                self._process(value)
                return dict(request_sha256=fingerprint(request),monitor_sha256=fingerprint(reference),service=qualified)
            proof=observed()
            require(observed()==proof,'event service changed during qualification')
            self._subscription(value['subscription'],request)
            require(value['proof'] is None or value['proof']==proof,'first monitored generation cannot be replaced')
            if value['proof'] is None:
                value.update(proof=deepcopy(proof));self._save(value)
            return proof
