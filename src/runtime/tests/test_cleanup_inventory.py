import json

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from test_runtime import runtime,request,stop,run


def test_finalization_inventory_requires_cleaned_birth_and_stopped_node(runtime):
    engine,journal,docker,linux=runtime
    run(engine,journal,request())
    value=engine.inspect('demo','R1')['cleanup_inventory']
    assert value['nodes']==['R1'] and set(value['blocked'])=={'nodes','workload_generations','resources'}
    run(engine,journal,stop())
    assert engine.inspect('demo','R1')['cleanup_inventory']=={'nodes':[],'blocked':[]}


@pytest.mark.parametrize('phase',['queued','applying','recovery_required','awaiting_finalization'])
def test_unrelated_native_operation_is_a_lab_finalization_veto(runtime,phase):
    engine,journal,docker,linux=runtime
    run(engine,journal,request());run(engine,journal,stop())
    op=journal.submit(request(node_id='R2',request_id='other'))
    journal.db.execute('UPDATE operations SET phase=? WHERE id=?',(phase,op['id']))
    value=engine.inspect('demo','R1')['cleanup_inventory']
    assert value['nodes']==['R2'] and 'operations' in value['blocked']
    assert cleanup_inventory(journal,'other-lab')=={'nodes':[],'blocked':[]}


@pytest.mark.parametrize('table',['local_bridges','local_vxlans'])
def test_primitive_ownership_is_scoped_and_unqualified_legacy_blocks(runtime,table):
    engine,journal,docker,linux=runtime
    journal.db.execute(f'INSERT INTO {table} VALUES(?,?,?)',('a'*64,json.dumps({'lab_id':'other'}),'active'))
    assert cleanup_inventory(journal,'demo')['blocked']==[]
    assert cleanup_inventory(journal,'other')['blocked']==[table]
    journal.db.execute(f'UPDATE {table} SET payload=?',(json.dumps({}),))
    assert cleanup_inventory(journal,'demo')['blocked']==[table]
    journal.db.execute(f"UPDATE {table} SET phase='cleaned'")
    assert cleanup_inventory(journal,'demo')['blocked']==[]
