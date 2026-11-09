"""Inert Docker exec delivery, identity and recovery boundaries."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from jumphost_cli_execution import Execution


class World:
    def __init__(self):
        self.owner = {'container_id': 'a' * 64, 'nonce': 'b' * 32, 'namespace': 'original'}
        self.nonce = 'c' * 32
        self.config = {'User': 'labuser', 'Cmd': ['python3', '-I', '-c', 'frozen-code', self.nonce],
                       **{key: False for key in ('AttachStdin', 'AttachStdout', 'AttachStderr', 'Tty', 'Privileged')}}
        self.exec = None
        self.extra = []
        self.calls = []
        self.failure = None
        self.result = {'nonce': self.nonce, 'exit_verified': True, 'marker_seen_before_input_close': True}

    def request(self, method, path, payload=None):
        if method == 'GET':
            assert path == '/exec/' + 'd' * 64 + '/json'
            return deepcopy(self.exec)
        self.calls.append((method, path, deepcopy(payload)))
        if path.endswith('/exec'):
            self.exec = {'ID': 'd' * 64, 'ContainerID': self.owner['container_id'],
                         'ProcessConfig': {'tty': False, 'entrypoint': 'python3',
                                           'arguments': self.config['Cmd'][1:], 'privileged': False, 'user': 'labuser'},
                         'OpenStdin': False, 'OpenStdout': False, 'OpenStderr': False,
                         'Running': False, 'Pid': 0, 'ExitCode': None}
            if self.failure == 'create-ack':
                self.failure = None
                raise OSError('lost create reply')
            return {'Id': 'd' * 64}
        assert path.endswith('/start')
        if self.failure == 'start-before':
            self.failure = None
            raise OSError('start outcome uncertain')
        if self.failure == 'running':
            self.exec.update(Running=True, Pid=42)
            return None
        self.exec.update(ExitCode=0)
        if self.failure == 'start-ack':
            self.failure = None
            raise OSError('lost start reply')

    def observe(self):
        ids = [] if self.exec is None or self.exec['ExitCode'] is not None else [self.exec['ID']]
        return {'owner': deepcopy(self.owner), 'exec_ids': ids + self.extra}

    def open(self, tmp_path):
        return Execution(tmp_path / 'exec.json', self, self.owner, self.config, self.nonce,
                         self.observe, lambda record, value: deepcopy(self.result))


def test_completed_execution_reopens_and_replays_without_create_or_start(tmp_path):
    world = World()
    result = world.open(tmp_path).run()
    assert result['phase'] == 'completed' and result['exit_verified']
    assert len(world.calls) == 2
    assert world.open(tmp_path).verify_completed() == result and len(world.calls) == 2


@pytest.mark.parametrize('failure', ['create-ack', 'start-ack'])
def test_lost_reply_recovers_same_exec_without_duplicate_mutation(tmp_path, failure):
    world = World()
    world.failure = failure
    with pytest.raises(OSError):
        world.open(tmp_path).run()
    assert world.open(tmp_path).run()['phase'] == 'completed'
    assert len(world.calls) == 2


def test_start_uncertain_never_sends_second_start(tmp_path):
    world = World()
    world.failure = 'start-before'
    with pytest.raises(OSError):
        world.open(tmp_path).run()
    with pytest.raises(RuntimeError, match='no second start'):
        world.open(tmp_path).run()
    assert len(world.calls) == 2


def test_missing_exec_after_uncertain_create_never_creates_again(tmp_path):
    world = World()
    world.failure = 'create-ack'
    with pytest.raises(OSError):
        world.open(tmp_path).run()
    world.exec = None
    with pytest.raises(RuntimeError, match='no second create'):
        world.open(tmp_path).run()
    assert len(world.calls) == 1


@pytest.mark.parametrize('conflict', ['owner', 'exec', 'extra'])
def test_recovery_rejects_replacements_before_start(tmp_path, conflict):
    world = World()
    original = world.open(tmp_path)
    original.prepare()
    if conflict == 'owner':
        world.owner['namespace'] = 'replacement'
    elif conflict == 'exec':
        world.exec['ContainerID'] = 'e' * 64
    else:
        world.extra = ['e' * 64]
    with pytest.raises(RuntimeError):
        original.run()
    assert len(world.calls) == 1


def test_running_exec_retains_recovery_without_restarting(tmp_path):
    world = World()
    world.failure = 'running'
    execution = world.open(tmp_path)
    with pytest.raises(RuntimeError, match='cleanup pending'):
        execution.run(timeout=.01)
    with pytest.raises(RuntimeError, match='recovery pending'):
        execution.verify_completed()
    assert len(world.calls) == 2 and not execution.record['exit_verified']


@pytest.mark.parametrize('result', [None, {}, {'nonce': 'wrong', 'exit_verified': True},
                                    {'nonce': 'c' * 32, 'exit_verified': False}])
def test_exec_exit_alone_never_qualifies_client_result(tmp_path, result):
    world = World()
    world.result = result
    execution = world.open(tmp_path)
    with pytest.raises(RuntimeError, match='not qualified'):
        execution.run()
    assert not execution.record['exit_verified']


def test_save_failure_prevents_remote_create(tmp_path, monkeypatch):
    world = World()
    execution = world.open(tmp_path)
    def fail():
        raise OSError('journal unavailable')
    monkeypatch.setattr(execution, 'save', fail)
    with pytest.raises(OSError):
        execution.run()
    assert not world.calls


def test_unqualified_exec_options_are_rejected_before_intent(tmp_path):
    world = World()
    world.config['Env'] = ['UNQUALIFIED=1']
    with pytest.raises(ValueError):
        world.open(tmp_path)
    assert not world.calls and not (tmp_path / 'exec.json').exists()


@pytest.mark.parametrize('boundary', ['create', 'start'])
def test_rechecks_owner_after_durable_intent_before_remote_mutation(tmp_path, monkeypatch, boundary):
    world = World()
    execution = world.open(tmp_path)
    if boundary == 'start':
        execution.prepare()
    save = execution.save

    def replace_owner_after_save():
        save()
        world.owner['namespace'] = 'replacement-after-checkpoint'

    monkeypatch.setattr(execution, 'save', replace_owner_after_save)
    with pytest.raises(RuntimeError, match='generation differs'):
        execution.run()
    assert len(world.calls) == (1 if boundary == 'start' else 0)


def test_completed_output_cannot_change_during_replay(tmp_path):
    world = World()
    execution = world.open(tmp_path)
    execution.run()
    world.result['unexpected'] = True
    with pytest.raises(RuntimeError, match='result changed'):
        world.open(tmp_path).verify_completed()
    assert len(world.calls) == 2


def test_completed_verification_is_readonly_and_never_prepares_or_saves(tmp_path,monkeypatch):
    world=World();actor=world.open(tmp_path);actor.run()
    before=actor.path.read_bytes()
    monkeypatch.setattr(actor,'prepare',lambda:pytest.fail('readonly verification prepared an execution'))
    monkeypatch.setattr(actor,'save',lambda:pytest.fail('readonly verification wrote a journal'))
    assert actor.verify_completed()['phase']=='completed'
    assert actor.path.read_bytes()==before and len(world.calls)==2


def test_readonly_constructor_never_creates_missing_journal(tmp_path):
    world=World()
    with pytest.raises(RuntimeError,match='journal missing'):
        Execution(tmp_path/'missing.json',world,world.owner,world.config,world.nonce,
                  world.observe,lambda *args:world.result,readonly=True)
    assert not (tmp_path/'missing.json').exists() and not world.calls
