import copy

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vxlan import VxlanManager, PREF


class Crash(BaseException):
    pass


class Linux:
    def __init__(self):
        self.source = {'ifname': 'rt-0123456789ab', 'ifindex': 10, 'ifalias': 'dnlab-runtime:fixture',
                       'address': '02:00:00:00:00:01', 'link_index': 11, 'linkinfo': {'info_kind': 'veth'}}
        self.records = [self.source, {'ifname': 'underlay0', 'ifindex': 2, 'mtu': 1500}]
        self.qd = {}
        self.rules = {}
        self.calls = []
        self.fail_after = None
        self.crash = False
        self.namespace_identity = {'boot_id': 'fixture', 'device': 4, 'inode': 100}

    def network_identity(self):
        return dict(self.namespace_identity)

    def links(self):
        return copy.deepcopy(self.records)

    def qdiscs(self, name):
        return copy.deepcopy(self.qd.get(name, []))

    def filters(self, name):
        return copy.deepcopy(self.rules.get(name, []))

    def run(self, args):
        self.calls.append(args)
        if args[:3] == ['ip', 'link', 'add']:
            name = args[3]
            value = lambda key: args[args.index(key)+1]
            self.records.append({'ifname': name, 'ifindex': 20, 'address': value('address'),
                                 'mtu': int(value('mtu')), 'altnames': [], 'flags': [],
                                 'linkinfo': {'info_kind': 'vxlan', 'info_data': {
                                     'id': int(value('id')), 'remote': value('remote'), 'local': value('local'),
                                     'link': value('dev'), 'port': int(value('dstport')), 'learning': True}}})
        elif args[:3] == ['ip', 'link', 'property']:
            record = next(x for x in self.records if x['ifname'] == args[5])
            record['altnames'].append(args[7])
        elif args[:3] == ['ip', 'link', 'set']:
            record = next(x for x in self.records if x['ifname'] == args[4])
            if args[5] == 'alias':
                record['ifalias'] = args[6]
            else:
                record['flags'] = ['UP']
        elif args[:3] == ['ip', 'link', 'delete']:
            name = args[4]
            self.records = [x for x in self.records if x['ifname'] != name]
            self.rules.pop(name, None)
            self.qd.pop(name, None)
        elif args[:2] == ['tc', 'qdisc']:
            name = args[4]
            if args[2] == 'add':
                self.qd[name] = [{'kind': 'ingress'}]
            else:
                self.qd.pop(name, None)
        elif args[:2] == ['tc', 'filter']:
            name = args[4]
            if args[2] == 'add':
                self.rules[name] = [{'kind': 'matchall', 'pref': PREF, 'protocol': 'all', 'chain': 0,
                                     'options': {'handle': '0x1', 'actions': [{'kind': 'mirred',
                                         'mirred_action': 'redirect', 'direction': 'egress', 'to_dev': args[args.index('redirect')+2], 'cookie':args[args.index('cookie')+1], 'index':len(self.calls), 'ref':1, 'bind':1,
                                         'control_action': {'type': 'stolen'}}]}}]
            else:
                self.rules.pop(name, None)
        else:
            raise AssertionError(args)
        if self.fail_after == len(self.calls):
            self.fail_after = None
            raise Crash() if self.crash else RuntimeError('lost mutation response')


@pytest.fixture
def fixture(tmp_path):
    journal = Journal(tmp_path)
    linux = Linux()
    manager = VxlanManager(journal, linux)
    identity = VxlanIdentity('lab1', 'link1', linux.source['ifname'], 3001)
    yield manager, linux, identity
    journal.close()


def create(manager, linux, identity):
    return manager.create(identity, source=linux.source, underlay='underlay0',
                          local='198.18.201.1', remote='198.18.201.2', mtu=1450)


def assert_clean(manager, linux, identity):
    assert manager.row(identity.digest)['phase'] == 'cleaned'
    assert linux.records == [linux.source, {'ifname': 'underlay0', 'ifindex': 2, 'mtu': 1500}]
    assert not linux.rules and not linux.qd


@pytest.mark.parametrize('phase',['creating','active','deleting','recovery_required','cleaned'])
def test_bridge_reservation_blocks_vxlan_until_cleanup(fixture,phase):
    import json
    manager,linux,identity=fixture
    with manager.journal.transaction():
        manager.journal.db.execute('CREATE TABLE local_bridges (id TEXT PRIMARY KEY,payload TEXT NOT NULL,phase TEXT NOT NULL)')
        manager.journal.db.execute('INSERT INTO local_bridges VALUES(?,?,?)',
            ('bridge-owner',json.dumps({'config':{'sources':[{'ifname':linux.source['ifname']},{'ifname':'other-source'}]}}),phase))
    if phase=='cleaned':
        create(manager,linux,identity);manager.delete(identity);assert_clean(manager,linux,identity)
    else:
        with pytest.raises(Conflict,match='reserved'):create(manager,linux,identity)
        assert not linux.calls and manager.row(identity.digest) is None


def test_retry_refuses_conflicting_reservation_without_changing_active_vxlan(fixture):
    import json
    manager,linux,identity=fixture;create(manager,linux,identity)
    with manager.journal.transaction():
        manager.journal.db.execute('CREATE TABLE local_bridges (id TEXT PRIMARY KEY,payload TEXT NOT NULL,phase TEXT NOT NULL)')
        manager.journal.db.execute('INSERT INTO local_bridges VALUES(?,?,?)',
            ('legacy-conflict',json.dumps({'config':{'sources':[{'ifname':linux.source['ifname']}]}}),'active'))
    count=len(linux.calls)
    with pytest.raises(Conflict,match='reserved'):create(manager,linux,identity)
    assert len(linux.calls)==count and manager.row(identity.digest)['phase']=='active'
    manager.verify(identity,manager.row(identity.digest)['payload'])


def test_active_retry_and_delete_are_idempotent(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    calls = len(linux.calls)
    create(manager, linux, identity)
    assert len(linux.calls) == calls
    manager.delete(identity)
    calls = len(linux.calls)
    manager.delete(identity)
    assert len(linux.calls) == calls
    assert_clean(manager, linux, identity)


@pytest.mark.parametrize('step', range(1, 10))
def test_lost_response_at_each_mutation_rolls_back_only_owned_resources(fixture, step):
    manager, linux, identity = fixture
    linux.fail_after = step
    with pytest.raises(RuntimeError, match='lost mutation response'):
        create(manager, linux, identity)
    assert_clean(manager, linux, identity)


@pytest.mark.parametrize('step', [1, 2, 3, 6, 8, 9])
def test_crash_replay_cleans_partial_creation_without_implicit_recreate(fixture, step):
    manager, linux, identity = fixture
    linux.fail_after, linux.crash = step, True
    with pytest.raises(Crash):
        create(manager, linux, identity)
    assert manager.row(identity.digest)['phase'] == 'creating'
    restarted = VxlanManager(manager.journal, linux)
    with pytest.raises(Conflict, match='explicit recovery'):
        create(restarted, linux, identity)
    restarted.recover(identity)
    assert_clean(restarted, linux, identity)


def test_existing_source_filters_rejected_before_mutation(fixture):
    manager, linux, identity = fixture
    linux.rules[identity.host_endpoint] = [{'kind': 'flower', 'pref': 40}]
    with pytest.raises(Conflict, match='already has filters'):
        create(manager, linux, identity)
    assert not linux.calls and manager.row(identity.digest) is None


def test_source_replacement_after_commit_is_preserved(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    calls = len(linux.calls)
    linux.source['ifindex'] += 1
    with pytest.raises(Conflict, match='source identity changed'):
        manager.delete(identity)
    assert len(linux.calls) == calls
    assert manager.row(identity.digest)['phase'] == 'recovery_required'


def test_foreign_tunnel_replacement_after_commit_is_preserved(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    calls = len(linux.calls)
    linux.records[-1]['ifalias'] = 'foreign'
    with pytest.raises(Conflict, match='creator'):
        manager.delete(identity)
    assert len(linux.calls) == calls


def test_foreign_filter_after_commit_is_preserved(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    calls = len(linux.calls)
    linux.rules[identity.host_endpoint].append({'kind': 'flower', 'pref': 40})
    with pytest.raises(Conflict, match='foreign'):
        manager.delete(identity)
    assert len(linux.calls) == calls


def test_preexisting_empty_clsact_is_preserved(fixture):
    manager, linux, identity = fixture
    linux.qd[identity.host_endpoint] = [{'kind': 'clsact'}]
    create(manager, linux, identity)
    manager.delete(identity)
    assert linux.qd == {identity.host_endpoint: [{'kind': 'clsact'}]}
    assert not linux.rules


def test_foreign_creator_mac_before_alias_is_never_adopted(fixture):
    manager, linux, identity = fixture
    linux.fail_after, linux.crash = 1, True
    with pytest.raises(Crash):
        create(manager, linux, identity)
    linux.records[-1]['address'] = '02:00:00:00:00:ff'
    calls = len(linux.calls)
    with pytest.raises(Conflict, match='creator'):
        manager.recover(identity)
    assert len(linux.calls) == calls
    assert manager.row(identity.digest)['phase'] == 'recovery_required'


def test_blank_alias_after_commit_cannot_reenter_bootstrap_adoption(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    linux.records[-1].pop('ifalias')
    calls = len(linux.calls)
    with pytest.raises(Conflict, match='creator'):
        manager.delete(identity)
    assert len(linux.calls) == calls


@pytest.mark.parametrize('field,value', [('boot_id', 'other-boot'), ('inode', 101)])
def test_namespace_or_boot_replacement_rejects_recovery_before_mutation(fixture, field, value):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    linux.namespace_identity[field] = value
    count = len(linux.calls)
    with pytest.raises(Conflict, match='namespace or host boot'):
        manager.recover(identity)
    assert len(linux.calls) == count


def test_underlay_replacement_is_detected_but_owned_tunnel_can_be_cleaned(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    original = linux.records[1]
    original['ifname'] = 'old-underlay'
    linux.records[-1]['linkinfo']['info_data']['link'] = 'old-underlay'
    linux.records.insert(1, {'ifname': 'underlay0', 'ifindex': 99, 'mtu': 1500})
    with pytest.raises(Conflict, match='underlay identity'):
        manager.verify(identity, manager.row(identity.digest)['payload'])
    manager.delete(identity)
    assert original in linux.records
    assert any(x.get('ifindex') == 99 for x in linux.records)
    assert manager.row(identity.digest)['phase'] == 'cleaned'


def test_underlay_mtu_decrease_rejected_without_reconfiguration(fixture):
    manager, linux, identity = fixture
    create(manager, linux, identity)
    linux.records[1]['mtu'] = 1400
    count = len(linux.calls)
    with pytest.raises(Conflict, match='MTU decreased'):
        create(manager, linux, identity)
    assert len(linux.calls) == count
    manager.delete(identity)


@pytest.mark.parametrize('tamper',[None,'cookie','index','missing-proof','target-replaced'])
def test_vxlan_cleanup_after_source_disappearance_requires_action_proof(fixture,tamper):
    manager,linux,identity=fixture
    create(manager,linux,identity)
    original=copy.deepcopy(linux.source)
    linux.records=[v for v in linux.records if v['ifname']!=original['ifname']]
    linux.rules.pop(original['ifname'],None);linux.qd.pop(original['ifname'],None)
    action=linux.rules[identity.kernel_name][0]['options']['actions'][0]
    action['to_dev']='*'
    if tamper in ('cookie','index'):action[tamper]='foreign'
    if tamper=='target-replaced':linux.records.append({**original,'ifindex':99})
    if tamper=='missing-proof':
        row=manager.row(identity.digest);row['payload'].pop('tc_proofs')
        manager.save(identity.digest,row['payload'],row['phase'])
    before=list(linux.calls)
    if tamper is None:
        manager.cleanup_preflight(identity,manager.row(identity.digest)['payload'])
        manager.delete(identity)
        assert manager.row(identity.digest)['phase']=='cleaned'
    else:
        with pytest.raises(Conflict):manager.cleanup_preflight(identity,manager.row(identity.digest)['payload'])
        with pytest.raises(Conflict):manager.delete(identity)
        assert linux.calls==before
