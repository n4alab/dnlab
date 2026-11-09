"""Exec ownership and uncertainty boundaries, with no native packet processes."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from dnlab_multinode.services.jumphost_host import JumphostError
from dnlab_multinode.services.management_probe_exec import Execution
from tests.test_management_probe_host import fixture
from tests.test_management_packet_probes import packet_worker,execution,run_packets


def test_nonblocking_start_releases_permit_and_reuses_original_exec(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read())
    w.operate('prepare-packets',expected_birth=birth);identity=execution(w);d.packet_behavior='running'
    for _ in range(2):
        result=w.operate('start-packets',expected_birth=birth,expected_execution=identity)
        assert result['packet_phase']=='applying' and not result['packet_execution']['exit_verified']
        assert [v['kind'] for v in result['packet_execution']['observations']]==['birth','permit']
    assert d.exec_creates==d.exec_starts==len(calls)==1
    with pytest.raises(JumphostError):w.operate('cleanup',expected_birth=birth,expected_execution=identity)
    d.packet_behavior='success'
    assert run_packets(w)['packet_phase']=='completed' and d.exec_starts==1


def test_nonblocking_start_requires_both_original_proofs(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read())
    w.operate('prepare-packets',expected_birth=birth);identity=execution(w)
    for kwargs in ({},{'expected_birth':birth},{'expected_birth':dict(birth,nonce='f'*32),'expected_execution':identity},
            {'expected_birth':birth,'expected_execution':dict(identity,id='f'*64)}):
        with pytest.raises(JumphostError):w.operate('start-packets',**kwargs)
    assert d.exec_starts==0 and not calls


@pytest.mark.parametrize('phase',['create','start'])
def test_lost_exec_response_recovers_original_id_without_duplicate_start(fixture,phase):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read());d.exec_lost=phase
    with pytest.raises(JumphostError):run_packets(w)
    d.exec_lost=None
    assert run_packets(w)['packet_phase']=='completed'
    assert d.exec_creates==d.exec_starts==len(calls)==1
    assert w.birth(w.read())==birth and w.read()['packet_execution']['exit_verified']
    w.operate('cleanup',expected_birth=birth,expected_execution=execution(w))


def test_uncertain_absent_create_never_allocates_another_exec(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read());d.exec_lost='before-create'
    with pytest.raises(JumphostError):w.operate('prepare-packets',expected_birth=birth)
    d.exec_lost=None
    for action in ('prepare-packets','cleanup'):
        with pytest.raises(JumphostError,match='unresolved'):
            w.operate(action,expected_birth=birth)
    assert d.exec_creates==1 and d.exec_starts==0 and not calls and w.read()['phase']=='active'


def test_start_uncertain_but_inactive_never_reissues_start(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read())
    w.operate('prepare-packets',expected_birth=birth);r=w.read();r['packet_execution']['start_attempted']=True;r['packet_execution']['phase']='starting';w.save(r)
    with pytest.raises(JumphostError,match='start unresolved'):run_packets(w)
    with pytest.raises(JumphostError,match='start unresolved'):
        w.operate('cleanup',expected_birth=birth,expected_execution=execution(w))
    assert not calls and d.exec_starts==0


@pytest.mark.parametrize('field',['ID','ContainerID','ProcessConfig','OpenStdin','Running','Pid'])
def test_foreign_exec_metadata_blocks_start_and_cleanup(fixture,field):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read());w.operate('prepare-packets',expected_birth=birth)
    row=d.execs[execution(w)['id']]
    if field in ('ID','ContainerID'):row[field]='f'*64
    if field=='ProcessConfig':row[field]['arguments']=['foreign']
    if field=='OpenStdin':row[field]=True
    if field=='Running':row[field]='true'
    if field=='Pid':row[field]=-1
    before=deepcopy((d.values,links.host,links.peer));count=len(d.calls)
    for action in ('packets','cleanup'):
        with pytest.raises(JumphostError):w.operate(action,expected_birth=birth,expected_execution=execution(w))
    assert before==(d.values,links.host,links.peer) and d.exec_starts==0 and not calls
    assert all(method=='GET' for method,path in d.calls[count:])


def test_foreign_exec_before_own_create_prevents_cleanup(fixture):
    w,d,links,calls=packet_worker(fixture);r=w.operate('ensure');d.values[r['container_id']]['ExecIDs']=['f'*64]
    with pytest.raises(JumphostError,match='unqualified exec'):
        w.operate('cleanup',expected_birth=w.birth(r))
    assert d.values and d.exec_creates==0


@pytest.mark.parametrize('action',['inspect','prepare-packets','packets','cleanup'])
def test_replaced_expected_exec_identity_is_rejected_under_lock(fixture,action):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');birth=w.birth(w.read());w.operate('prepare-packets',expected_birth=birth)
    expected=deepcopy(execution(w));expected['id']='f'*64;before=w.path.read_bytes(),deepcopy(d.values),len(d.calls)
    with pytest.raises(JumphostError,match='packet exec differs'):
        w.operate(action,expected_birth=birth,expected_execution=expected)
    assert w.path.read_bytes()==before[0] and d.values==before[1] and not d.calls[before[2]:] and not calls


def test_failed_exec_retains_partial_error_and_allows_only_verified_cleanup(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');d.packet_behavior='failure'
    with pytest.raises(JumphostError,match='failed; evidence retained'):run_packets(w)
    record=w.read();op=record['packet_execution']
    assert record['packet_phase']=='failed' and op['exit_verified'] and op['exit_code']==1
    assert op['error']=={'type':'TimeoutError','message':'fixture packet failure'}
    assert [row['kind'] for row in op['observations']]==['birth','permit','failed']
    with pytest.raises(JumphostError):run_packets(w)
    assert d.exec_starts==1
    assert w.operate('cleanup',expected_birth=w.birth(record),expected_execution=execution(w))['phase']=='cleaned'


def test_failed_create_intent_checkpoint_blocks_docker_exec_creation(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');save=w.save
    def failed(record):
        if record['packet_execution']['create_attempted']:raise OSError('exec intent fsync')
        save(record)
    w.save=failed
    with pytest.raises(OSError):w.operate('prepare-packets',expected_birth=w.birth(w.read()))
    assert not calls and not d.exec_creates and not w.read()['packet_execution']['create_attempted']


@pytest.mark.parametrize('asset',['program','output'])
def test_replaced_asset_is_preserved_before_exec_start(fixture,asset):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure');r=w.read();path=Path(r['packet_execution']['files'][asset]['path'])
    other=path.with_suffix('.replacement');other.write_text(path.read_text());other.chmod(0o600);other.replace(path)
    before=path.read_bytes(),deepcopy(d.values)
    with pytest.raises(JumphostError):w.operate('prepare-packets',expected_birth=w.birth(r))
    assert (path.read_bytes(),d.values)==before and not d.exec_creates


def test_incomplete_output_after_verified_exit_is_failed_not_ready_and_can_be_cleaned(fixture):
    w,d,links,calls=packet_worker(fixture);w.operate('ensure')
    def incomplete(row):
        if not row['Running']:return
        record=w.read();path=Path(record['packet_execution']['files']['output']['path'])
        if '"permit"' not in path.read_text():return
        with path.open('ab') as stream:stream.write(b'{"partial":');stream.flush()
        row.update(Running=False,Pid=0,ExitCode=137);d.values[row['ContainerID']]['ExecIDs']=[]
    d.on_exec_inspect=incomplete
    with pytest.raises(JumphostError,match='failed; evidence retained'):run_packets(w)
    record=w.read();assert record['packet_phase']=='failed' and record['packet_execution']['exit_verified']
    assert record['packet_execution']['partial_tail']==b'{"partial":'.hex() and 'packet_result' not in record
    assert w.operate('cleanup',expected_birth=w.birth(record),expected_execution=execution(w))['phase']=='cleaned'


@pytest.mark.parametrize('change',['capability','mount-source','mount-mode','program-content','progress-nonce'])
def test_new_execution_profile_rejects_tampering(fixture,change):
    w,d,links,calls=packet_worker(fixture);record=w.operate('ensure');value=d.values[record['container_id']]
    if change=='capability':value['HostConfig']['CapAdd']=['NET_ADMIN','NET_RAW']
    if change=='mount-source':value['Mounts'][0]['Source']='/foreign'
    if change=='mount-mode':value['Mounts'][0]['RW']=True
    if change=='program-content':Path(record['packet_execution']['files']['program']['path']).write_text('foreign')
    if change=='progress-nonce':
        w.operate('prepare-packets',expected_birth=w.birth(record));d.exec_lost='start'
        with pytest.raises(JumphostError):run_packets(w)
        d.exec_lost=None
        path=Path(record['packet_execution']['files']['output']['path']);rows=[json.loads(line) for line in path.read_text().splitlines()]
        rows[0]['nonce']='f'*32;path.write_text(''.join(json.dumps(v)+'\n' for v in rows))
    before=deepcopy((d.values,links.host,links.peer));starts=d.exec_starts
    with pytest.raises((JumphostError,ValueError)):run_packets(w)
    assert before==(d.values,links.host,links.peer) and d.exec_starts==starts
