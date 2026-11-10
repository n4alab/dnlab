"""Keep prepared unit metadata historical while observing a different boot.

No configuration driver is instantiated: its constructor would initialize
schema. The readonly query must match the complete original prepared record.
"""
from copy import deepcopy
import json

from dnlab_runtime.libvirt_configuration import compile_revision
from dnlab_runtime.manifest import Conflict,fingerprint


class UnitPostBootCollection:
    def __init__(self,reader,journal,*,reference,effective_source,directory_reference):
        if (reference.get('phase')!='prepared' or reference.get('proof') is not None
                or reference.get('installation')!=effective_source
                or reference.get('source_sha256')!=fingerprint(effective_source)
                or reference.get('plan')!=compile_revision(effective_source)
                or effective_source.get('postboot',{}).get('recovery_id')!=directory_reference['recovery']['id']):
            raise Conflict('original prepared unit observation lineage differs')
        self.reader,self.journal,self.reference=reader,journal,deepcopy(reference)

    def original(self):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM libvirt_configuration_revisions WHERE id=?',
                (self.reference['id'],)).fetchone()
        if row is None:raise Conflict('original prepared unit observation missing')
        value=json.loads(row['payload'])
        if (value!=self.reference or row['fingerprint']!=fingerprint(value)
                or row['id']!=value['id'] or row['installation_id']!=value['installation']['id']):
            raise Conflict('original prepared unit observation changed')
        return value

    def collect(self):
        self.original()
        observed=self.reader.collect()
        self.original()
        return dict(observed,scope='unit-postboot-readonly',qualified=False,
            historical_unit_reference=deepcopy(self.reference),
            historical_unit_sha256=fingerprint(self.reference),unit_apply_permitted=False)
