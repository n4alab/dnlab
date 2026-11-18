"""Bind a paused-creation QMP request to the original received start event.

The callback's libvirt incarnation ID is never a host PID. Old raw events
without that ID remain history; no current-domain lookup can fill the gap.
This provider registers no monitor, sends no QMP and never starts/resumes a VM.
"""
from copy import deepcopy
import json
from xml.etree import ElementTree as ET

from .libvirt_observer import xml_fingerprint
from .manifest import fingerprint, canonical
from .vm_template import fields, require


class LibvirtCreationEvents:
    def __init__(self,source):
        self.source,self.journal=source,source.journal
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_libvirt_creation_events '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _event(self,source,sequence):
        row=self.journal.db.execute('SELECT * FROM vm_libvirt_raw_events WHERE feed_id=? AND sequence=?',
                                    (self.source.feed.id,sequence)).fetchone()
        require(row is not None, 'original creation event missing')
        event=json.loads(row['payload'])
        require(fingerprint(event)==row['fingerprint'] and event['sequence']==row['sequence']==sequence
                and event['uuid']==source['birth']['uuid'] and type(event.get('domain_id')) is int
                and 0<=event['domain_id']<2**32-1, 'original creation event lacks a qualified domain incarnation')
        return event

    def _read(self,source):
        row=self.journal.db.execute('SELECT * FROM vm_libvirt_creation_events WHERE id=?',(source['id'],)).fetchone()
        require(row is not None, 'original creation event anchor missing')
        value=json.loads(row['payload'])
        fields(value,('birth','source_id','feed_id','collector_id','epoch_sha256','request_fingerprint',
                      'definition_sha256','event_sequence','event_sha256','query'),'original creation event anchor')
        current=self.source._definition(source)
        require(row['domain_uuid']==source['birth']['uuid'] and fingerprint(value)==row['fingerprint']
                and value['birth']==source['birth'] and value['source_id']==source['id']
                and value['feed_id']==self.source.feed.id and value['collector_id']==self.source.id
                and value['epoch_sha256']==self.source.epoch and value['request_fingerprint']==source['request_fingerprint']
                and value['definition_sha256']==current['boot']['definition_sha256']
                and value['event_sequence']==source['initial']['started'], 'original creation anchor lineage differs')
        event=self._event(source,value['event_sequence'])
        require(event['kind']=='lifecycle' and (event['event'],event['detail'])==(2,0)
                and fingerprint(event)==value['event_sha256'] and value['query']['domain_id']==event['domain_id']
                and value['query']['birth']==source['birth'] and value['query']['source_id']==source['id'],
                'original started event binding differs')
        return value

    def matches(self,source,event):
        if self.journal.db.execute('SELECT 1 FROM vm_libvirt_creation_events WHERE id=?',(source['id'],)).fetchone() is None:
            return True
        anchor=self._read(source)
        if event['kind']=='lifecycle' and event['event'] in (5,8):return True  # reducer requires recovery anyway
        return type(event.get('domain_id')) is int and event['domain_id']==anchor['query']['domain_id']

    def _domain(self,value,source):
        require(value['boot']['phase']=='start_requested' and source['phase']=='armed'
                and self.source._definition(source)==value, 'original acknowledged paused start checkpoint required')
        self.source.definitions._session(value)
        event=self._event(source,source['initial']['started'])
        require(event['kind']=='lifecycle' and (event['event'],event['detail'])==(2,0), 'original normal boot event required')
        domain=self.source.definitions.connection.lookupByUUIDString(value['birth']['uuid'])
        require(domain.UUIDString()==value['birth']['uuid'] and domain.ID()==event['domain_id']
                and domain.isActive()==1 and domain.isPersistent()==1 and domain.state(0)[0]==3,
                'paused domain differs from the original start event')
        for sequence in source['initial'].values():
            if sequence is not None:
                require(self._event(source,sequence)['domain_id']==event['domain_id'], 'boot notifications mix domain incarnations')
        persistent,live=domain.XMLDesc(2),domain.XMLDesc(0)
        persistent_sha256=xml_fingerprint(persistent,value['birth']);live_sha256=xml_fingerprint(live,value['birth'])
        require(persistent_sha256==value['ack']['persistent_sha256'], 'original creation definition differs')
        text=ET.fromstring(persistent).findtext('vcpu')
        require(isinstance(text,str) and text.isdecimal() and str(int(text))==text and 1<=int(text)<=256,
                'qualified initial CPU count required')
        require(domain.ID()==event['domain_id'] and domain.state(0)[0]==3, 'original creation changed during event observation')
        return dict(birth=deepcopy(value['birth']),source_id=source['id'],persistent_sha256=persistent_sha256,
                    live_sha256=live_sha256,domain_id=event['domain_id'],expected_cpus=int(text))

    @staticmethod
    def _request(anchor):return dict(**deepcopy(anchor['query']),creation_sha256=fingerprint(anchor))

    def request(self,value,domain):
        with self.journal.execution_lock:
            require(domain.UUIDString()==value['birth']['uuid'], 'original start response UUID differs')
            source=self.source._drain(value['boot']['source_id']);deadline=self.source.clock()+self.source.timeout
            while source['initial']['started'] is None:
                require(self.source.clock()<deadline, 'original creation start event not observed before deadline')
                self.source.pause(min(0.01,max(0,deadline-self.source.clock())))
                source=self.source._drain(source['id'])
            query=self._domain(value,source)
            if self.journal.db.execute('SELECT 1 FROM vm_libvirt_creation_events WHERE id=?',(source['id'],)).fetchone():
                anchor=self._read(source)
                require(anchor['query']==query, 'original creation anchor cannot be replaced')
                return self._request(anchor)
            event=self._event(source,source['initial']['started'])
            anchor=dict(birth=deepcopy(source['birth']),source_id=source['id'],feed_id=self.source.feed.id,
                        collector_id=self.source.id,epoch_sha256=self.source.epoch,request_fingerprint=source['request_fingerprint'],
                        definition_sha256=value['boot']['definition_sha256'],event_sequence=event['sequence'],
                        event_sha256=fingerprint(event),query=query)
            with self.journal.transaction():
                require(self._domain(value,source)==query, 'original creation changed before anchor commit')
                self.journal.db.execute('INSERT INTO vm_libvirt_creation_events VALUES(?,?,?,?)',
                    (source['id'],source['birth']['uuid'],canonical(anchor),fingerprint(anchor)))
            request=self._request(anchor)
            self.preflight(request)
            return request

    def preflight(self,request):
        """Observe the original anchor; never create one while checking QMP."""
        with self.journal.execution_lock:
            source=self.source._drain(request['source_id']);anchor=self._read(source)
            require(self._request(anchor)==request, 'QMP request differs from the original creation event anchor')
            value=self.source._definition(source)
            require(self._domain(value,source)==anchor['query'], 'original paused creation snapshot differs')
            source=self.source._drain(source['id'])
            require(self._read(source)==anchor, 'original creation event anchor changed during observation')
            return fingerprint(request)
