"""First received incarnation -> immutable QMP request, entirely synthetic."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from test_libvirt_boot_events import event_boot, boot, definition, template, instance


def intercept(e,action):
    capture=e.driver.capture_started
    def started(value,domain):
        action(value,domain)
        return capture(value,domain)
    e.driver.capture_started=started


def test_first_event_request_is_stable_and_preflight_cannot_create_an_anchor(event_boot):
    e=event_boot;requests=[]
    def observe(value,domain):
        missing=dict(birth=value['birth'],source_id=value['boot']['source_id'],creation_sha256='a'*64)
        with pytest.raises(RuntimeErrorBase,match='anchor missing'):e.source.query_preflight(missing)
        assert e.driver.journal.db.execute('SELECT count(*) FROM vm_libvirt_creation_events').fetchone()[0]==0
        request=e.source.creation_request(value,domain)
        assert e.source.query_preflight(request)==fingerprint(request)
        assert e.source.creation_request(value,domain)==request
        requests.append(request)
    intercept(e,observe)
    result=e.driver.apply(e.operation)
    assert result['boot']['phase']=='running' and len(requests)==1
    row=e.driver.journal.db.execute('SELECT * FROM vm_libvirt_creation_events').fetchone()
    anchor=json.loads(row['payload'])
    assert fingerprint(anchor)==requests[0]['creation_sha256']==row['fingerprint']
    assert anchor['event_sequence']==1 and requests[0]['domain_id']==22
    assert requests[0]['domain_id']!=result['boot']['process_record']['process']['pid']
    assert e.state['starts']==e.state['resumes']==1


@pytest.mark.parametrize('fault',['replaced','legacy_event','missing_started','mixed_pause'])
def test_live_lookup_never_fills_missing_or_foreign_first_event_proof(event_boot,fault):
    e=event_boot
    if fault=='missing_started':e.control['omit_started']=True
    def observe(value,domain):
        if fault=='replaced':e.control['domain_id']=23
        elif fault=='legacy_event':e.feed.queue[0].pop('domain_id')
        elif fault=='mixed_pause':e.feed.queue[1]['domain_id']=23
        e.source.creation_request(value,domain)
    intercept(e,observe)
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.driver.journal.db.execute('SELECT count(*) FROM vm_libvirt_creation_events').fetchone()[0]==0
    assert e.state['starts']==1 and e.state['resumes']==0 and e.state['cpu']==3


def test_changed_live_incarnation_refuses_original_qmp_preflight(event_boot):
    e=event_boot
    def observe(value,domain):
        request=e.source.creation_request(value,domain)
        row=tuple(e.driver.journal.db.execute('SELECT * FROM vm_libvirt_creation_events').fetchone())
        e.control['domain_id']=23
        with pytest.raises(RuntimeErrorBase):e.source.query_preflight(request)
        assert tuple(e.driver.journal.db.execute('SELECT * FROM vm_libvirt_creation_events').fetchone())==row
        e.control['domain_id']=22
    intercept(e,observe)
    assert e.driver.apply(e.operation)['boot']['phase']=='running'


def test_reboot_on_foreign_incarnation_never_renews_original_event_binding(event_boot):
    e=event_boot;intercept(e,lambda value,domain:e.source.creation_request(value,domain))
    result=e.driver.apply(e.operation)
    e.feed.emit(kind='reboot',domain_id=23)
    with pytest.raises(RuntimeErrorBase,match='domain incarnation'):e.source.verify(result['boot']['activation_ack'])
    assert e.state['starts']==e.state['resumes']==1


def test_creation_event_anchor_alone_protects_its_lab(event_boot,tmp_path):
    e=event_boot;intercept(e,lambda value,domain:e.source.creation_request(value,domain))
    result=e.driver.apply(e.operation)
    row=e.driver.journal.db.execute('SELECT * FROM vm_libvirt_creation_events').fetchone()
    journal=Journal(tmp_path/'anchor-only-journal')
    try:
        journal.db.execute('CREATE TABLE vm_libvirt_creation_events '
            '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        journal.db.execute('INSERT INTO vm_libvirt_creation_events VALUES(?,?,?,?)',tuple(row))
        assert cleanup_inventory(journal,result['birth']['lab_id'])==dict(
            nodes=[result['birth']['node_id']],blocked=['vm_libvirt_creation_events'])
        assert cleanup_inventory(journal,'unrelated-lab')==dict(nodes=[],blocked=[])
    finally:journal.close()
