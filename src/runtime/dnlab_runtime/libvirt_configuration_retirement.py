"""Append-only retirement of an untouched prepared revision after a boot change.

Source and complete observation providers are explicit. No files or services are
mutated. Legacy revision payloads stay byte-identical; retired IDs cannot act.
"""
from copy import deepcopy
import json

from .manifest import Conflict,canonical,fingerprint,identifier

TABLE='libvirt_configuration_retirements'


def retirement(journal,reference):
    row=journal.db.execute('SELECT * FROM '+TABLE+' WHERE revision_id=?',(reference['id'],)).fetchone()
    if row is None:return None
    value=json.loads(row['payload'])
    if (fingerprint(value)!=row['fingerprint'] or value.get('revision_id')!=reference['id']
            or value.get('id')!=row['id'] or value.get('reference_sha256')!=fingerprint(reference)
            or set(value)!={'id','revision_id','reference_sha256','current_source_sha256','context','window_sha256','observation'}):
        raise Conflict('original configuration retirement receipt differs')
    return value


class ConfigurationRetirement:
    def __init__(self,driver,*,source_reader,observer,window):
        if not callable(source_reader) or not callable(observer):raise Conflict('explicit current retirement observers required')
        self.driver,self.journal=driver,driver.journal
        self.source_reader,self.observer,self.window=source_reader,observer,window

    def _observe(self,reference,source):
        from .libvirt_configuration import UNIT,compile_revision
        if (reference['phase']!='prepared' or reference['proof'] is not None
                or source['id']!=reference['installation']['id']
                or source['context']['boot_id']==reference['installation']['context']['boot_id']
                or source['request']!=reference['installation']['request']
                or source['profile']!=reference['installation']['profile']
                or 'postboot' not in source or source['phase']!='installed_not_started'
                or compile_revision(source)['source_item']!=reference['plan']['source_item']):
            raise Conflict('untouched prepared revision and completed new-boot source required')
        expected=dict(context=deepcopy(source['context']),current_source_sha256=fingerprint(source),
            original_unit=deepcopy(reference['plan']['source_item']['proof']),
            staging=dict(path=reference['staging'],state='absent'),backup=dict(path=reference['backup'],state='absent'),
            services_inactive=True)
        self.window.verify(dict(spec={'key':'file:'+UNIT}),self.window.receipt['operation_id'],self.window.sha256)
        if self.window.receipt['context']!=source['context'] or self.window.receipt['targets']!=['file:'+UNIT]:
            raise Conflict('explicit current retirement window differs')
        observed=self.observer(deepcopy(reference),deepcopy(source))
        if observed!=expected:raise Conflict('complete untouched unit retirement preflight differs')
        if self.source_reader()!=source:raise Conflict('current retirement source changed')
        self.window.verify(dict(spec={'key':'file:'+UNIT}),self.window.receipt['operation_id'],self.window.sha256)
        return observed

    def retire(self,operation,reference):
        identifier(operation,'configuration retirement operation_id')
        with self.journal.execution_lock:
            if reference!=self.driver.read(reference['id']):raise Conflict('original prepared retirement reference differs')
            if operation in (reference['id'],reference['installation']['id']):raise Conflict('separate retirement operation required')
            if self.window.receipt['operation_id']!=operation:raise Conflict('original retirement window differs')
            source=self.source_reader();observed=self._observe(reference,source)
            receipt=dict(id=operation,revision_id=reference['id'],reference_sha256=fingerprint(reference),
                current_source_sha256=fingerprint(source),context=deepcopy(source['context']),
                window_sha256=self.window.sha256,observation=deepcopy(observed))
            prior=retirement(self.journal,reference)
            if prior is not None:
                if prior!=receipt:raise Conflict('original configuration retirement request differs')
                return deepcopy(prior)
            with self.journal.transaction():
                # Check again after entering the durable metadata boundary.
                if self.driver.read(reference['id'])!=reference or self._observe(reference,source)!=observed:
                    raise Conflict('configuration retirement changed before commit')
                self.journal.db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?)',
                    (operation,reference['id'],canonical(receipt),fingerprint(receipt)))
            return retirement(self.journal,reference)
