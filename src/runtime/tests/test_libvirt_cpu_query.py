"""Fixed QMP boundary; monitor, domain, runtime and all sources simulated."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_cpu_query import COMMAND, PausedCPUQuery, cpu_threads
from dnlab_runtime.libvirt_observer import xml_fingerprint
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from test_libvirt_event_feed import events, case
from test_libvirt_observer import observer, template, instance


def cpu(index,tid):
    return {'cpu-index':index,'thread-id':tid,'qom-path':f'/machine/cpu[{index}]','target':'x86_64'}


@pytest.fixture
def query(events,observer,tmp_path):
    e=events;_,birth,xml_state,_=observer
    journal=Journal(tmp_path/'qmp-journal')
    state=dict(id=22,cpu_state=3,calls=0,error=None,scope=True,epoch=dict(id='e'*32),reply=json.dumps({'return':[cpu(0,901)],'id':'libvirt-1'}))
    raw=e.case.domain;raw.uuid=birth['uuid']
    raw.ID=lambda:state['id'];raw.isActive=lambda:1;raw.isPersistent=lambda:1
    raw.state=lambda flags:(state['cpu_state'],0);raw.XMLDesc=lambda flags:xml_state['xml'][flags]
    request=dict(birth=deepcopy(birth),source_id='f'*32,creation_sha256='c'*64,
                 persistent_sha256=xml_fingerprint(xml_state['xml'][2],birth),
                 live_sha256=xml_fingerprint(xml_state['xml'][0],birth),domain_id=22,expected_cpus=1)
    def monitor(domain,command,flags):
        assert domain is raw and command==COMMAND and flags==0
        value=json.loads(journal.db.execute('SELECT payload FROM vm_qemu_cpu_queries').fetchone()[0])
        assert value['phase']=='requested' and value['expected_metadata_effect']=='custom-monitor'
        assert value['effect_may_have_occurred'] is True
        state['calls']+=1
        if state['error']:raise state['error']
        return state['reply']
    extension=SimpleNamespace(libvirt=e.case.sdk,VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT=0,qemuMonitorCommand=monitor)
    with e.case.connect(False) as connection:
        connection.events(check_loop=e.check_loop)
        manager=PausedCPUQuery(journal,connection,SimpleNamespace(check=lambda:deepcopy(state['epoch'])),extension,
                               preflight=lambda value:fingerprint(request) if state['scope'] else '0'*64)
        yield SimpleNamespace(manager=manager,request=request,journal=journal,state=state,connection=connection,
                              extension=extension,birth=birth)
    journal.close()


def test_only_fixed_query_is_dispatched_after_durable_effect_intent(query):
    e=query;result=e.manager.query(e.request)
    assert result['phase']=='completed' and result['cpus']==[dict(index=0,thread_id=901)]
    assert result['expected_metadata_effect']=='custom-monitor' and result['effect_may_have_occurred']
    assert e.manager.query(e.request)==result and e.state['calls']==1
    assert e.manager.read_completed(e.request)==result and e.state['calls']==1
    assert 'process_record' not in result and 'pid' not in result
    assert cleanup_inventory(e.journal,e.birth['lab_id'])==dict(nodes=[e.birth['node_id']],blocked=['vm_qemu_cpu_queries'])
    assert cleanup_inventory(e.journal,'unrelated-lab')==dict(nodes=[],blocked=[])


def test_lost_response_stays_pending_without_second_query(query):
    e=query;e.state['error']=OSError('lost original QMP response')
    with pytest.raises(OSError):e.manager.query(e.request)
    e.state['error']=None
    with pytest.raises(RuntimeErrorBase,match='not repeated'):e.manager.query(e.request)
    assert e.state['calls']==1


def test_read_completed_never_issues_a_query_for_missing_receipt(query):
    e=query
    with pytest.raises(RuntimeErrorBase,match='receipt missing'):e.manager.read_completed(e.request)
    assert e.state['calls']==0


@pytest.mark.parametrize('fault',['scope','domain_id','running','readonly','epoch','cpu_count'])
def test_unqualified_creation_refused_before_monitor_and_intent(query,fault):
    e=query
    if fault=='scope':e.state['scope']=False
    elif fault=='domain_id':e.state['id']+=1
    elif fault=='running':e.state['cpu_state']=1
    elif fault=='readonly':e.connection._readonly=True
    elif fault=='epoch':e.state['epoch']['id']='d'*32
    else:e.request['expected_cpus']=2
    with pytest.raises(RuntimeErrorBase):e.manager.query(e.request)
    assert e.state['calls']==0
    assert e.journal.db.execute('SELECT count(*) FROM vm_qemu_cpu_queries').fetchone()[0]==0


def test_recheck_after_intent_blocks_query_on_changed_creation(query,monkeypatch):
    e=query;transaction=e.journal.transaction;changed=[]
    from contextlib import contextmanager
    @contextmanager
    def checkpoint():
        with transaction():yield
        if not changed and e.journal.db.execute('SELECT count(*) FROM vm_qemu_cpu_queries').fetchone()[0]:
            changed.append(True);e.state['id']+=1
    monkeypatch.setattr(e.journal,'transaction',checkpoint)
    with pytest.raises(RuntimeErrorBase):e.manager.query(e.request)
    assert e.state['calls']==0
    assert json.loads(e.journal.db.execute('SELECT payload FROM vm_qemu_cpu_queries').fetchone()[0])['phase']=='pending'


@pytest.mark.parametrize('fault',['duplicate_tid','duplicate_index','boolean_tid','wrong_arch','count','unknown','error','nonfinite','duplicate_key'])
def test_response_is_typed_bounded_and_never_infers_a_pid(fault):
    value={'return':[cpu(0,900),cpu(1,901)],'id':'libvirt-7'}
    if fault=='duplicate_tid':value['return'][1]['thread-id']=900
    elif fault=='duplicate_index':value['return'][1]['cpu-index']=0
    elif fault=='boolean_tid':value['return'][0]['thread-id']=True
    elif fault=='wrong_arch':value['return'][0]['target']='s390x'
    elif fault=='count':value['return'].pop()
    elif fault=='unknown':value['return'][0]['extra']='unqualified'
    elif fault=='error':value={'error':{'class':'CommandNotFound','desc':'unavailable'}}
    elif fault=='nonfinite':value['return'][0]['thread-id']=float('nan')
    raw=json.dumps(value)
    if fault=='duplicate_key':raw='{"return":[],"return":[]}'
    with pytest.raises((RuntimeErrorBase,ValueError)):cpu_threads(raw,2)


def test_cpu_result_sorting_preserves_indexes_and_ignores_no_fields():
    value={'return':[cpu(1,901),cpu(0,900)],'id':'libvirt-12'}
    assert cpu_threads(json.dumps(value),2)==[dict(index=0,thread_id=900),dict(index=1,thread_id=901)]
