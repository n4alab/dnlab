"""Docker bind order must not weaken exact mount ownership checks."""
import pytest

from tests.test_jumphost_host import World, config
from tests.test_jumphost_dhcp import content
from dnlab_multinode.services.jumphost_host import JumphostError


def fixture(tmp_path):
    cfg=config();cfg['dhcp']=content();environment=World(cfg)
    worker=environment.worker(tmp_path/'journal');record=worker.operate('ensure',cfg)
    return environment,worker,record


def test_same_distinct_bind_mounts_reordered_are_the_same_generation(tmp_path):
    environment,worker,record=fixture(tmp_path)
    actual=environment.values[record['container_id']]['HostConfig']['Binds']
    assert len(actual)==2 and len(set(actual))==2
    actual.reverse();environment.calls.clear()
    assert worker.operate('read')==record


@pytest.mark.parametrize('difference',['duplicate','source','destination','permissions'])
def test_bind_order_equivalence_cannot_accept_different_mounts(tmp_path,difference):
    environment,worker,record=fixture(tmp_path)
    mounts=environment.values[record['container_id']]['HostConfig']['Binds']
    if difference=='duplicate':mounts[1]=mounts[0]
    if difference=='source':mounts[0]='/tmp/foreign:/etc/dnlab-dhcp:ro'
    if difference=='destination':mounts[0]=mounts[0].replace('/etc/dnlab-dhcp','/etc/foreign')
    if difference=='permissions':mounts[0]=mounts[0][:-2]+'rw'
    with pytest.raises(JumphostError):worker.operate('read')


@pytest.mark.parametrize('actual,expected', [
    (['/a:/target:ro','/b:/target:ro'],['/a:/target:ro','/b:/target:ro']),
    (['/a:/target:ro','/b:/target/../target:ro'],['/a:/target:ro','/b:/target/../target:ro']),
    (['/a:/target:ro','/b://target:ro'],['/a:/target:ro','/b://target:ro']),
    (['/a:/target:ro','/a:/target:ro'],['/a:/target:ro','/a:/target:ro']),
    (['/a:/target:ro'],['/a:/target:ro','/a:/target:ro']),
    (['/a:/target:rw'],['/a:/target:rw']),
    (['/a:relative:ro'],['/a:relative:ro']),
    (['relative:/target:ro'],['relative:/target:ro']),
    ('/a:/target:ro',['/a:/target:ro']),
    ([{}],['/a:/target:ro']),
])
def test_duplicate_or_malformed_mounts_never_qualify_even_when_equal(actual,expected):
    from dnlab_multinode.services.jumphost_host import same_bind_mounts
    assert not same_bind_mounts(actual,expected)


def test_ambiguous_desired_destinations_refused_before_container_create(tmp_path):
    cfg=config();cfg['dhcp']=content();cfg['binds']=['/tmp/foreign:/etc/dnlab-dhcp:ro']
    environment=World(cfg);worker=environment.worker(tmp_path/'journal')
    with pytest.raises(JumphostError,match='bind destinations'):worker.operate('ensure',cfg)
    assert not any(args[:2]==['docker','create'] for args in environment.calls)
    assert not worker.dhcp_directory(worker.read()).exists()


def test_lost_create_response_with_reordered_binds_recovers_original_id(tmp_path):
    cfg=config();cfg['dhcp']=content();environment=World(cfg);worker=environment.worker(tmp_path/'journal')
    environment.lost='create'
    with pytest.raises(JumphostError,match='lost'):worker.operate('ensure',cfg)
    original=next(iter(environment.values))
    environment.values[original]['HostConfig']['Binds'].reverse();environment.lost=None
    assert worker.operate('recover')['container_id']==original
    assert sum(args[:2]==['docker','create'] for args in environment.calls)==1
    assert worker.operate('delete')['phase']=='cleaned'
