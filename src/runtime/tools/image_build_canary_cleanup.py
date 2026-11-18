"""Retire only the original disposable canary after its restored hold.

Uses the persisted startup generation, one tracked policy update and pidfd TERM,
then ordinary NosFixture cleanup. Requested policy/TERM are never resent. A
known exited generation permits qualified removal/absence recovery only.
"""
from copy import deepcopy
import json
import uuid

from image_build_canary import qualify, POLICY
from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import fields, require


class CanaryCleanup:
    def __init__(self, fixture, session, operation):
        require(fixture.journal is session.runtime.journal, 'same original canary runtime journal required')
        self.fixture,self.session,self.operation=fixture,session,operation
        self.journal=fixture.journal
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS image_build_canary_cleanup '
                '(id TEXT PRIMARY KEY,container_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _owner(self):
        self.session.runtime.check()
        hold=self.session.hold.read(self.operation);birth=self.fixture.get()
        require(birth is not None
                and birth['original']['config']['Labels'].get('io.dnlab.spike')=='image-build-hold'
                and self.fixture.spec['container_name'].startswith('drsp-ibc-')
                and birth['container_id']==hold['actor']['container_id']==self.session.executor.engine.container_id,
                'original disposable image-build canary required')
        if hold['phase']!='restored':
            retirement=self._retirement(hold,birth)
            instance=dict(capture=deepcopy(self.session.profile['capture']),generation=deepcopy(self.session.profile['generation']),
                          actor=deepcopy(self.session.profile['actor']))
            owner=dict(fixture_id=birth['id'],container_id=birth['container_id'],hold_id=self.operation,
                       instance_sha256=fingerprint(instance),arm_retirement_id=retirement['id'],
                       config_sha256=fingerprint(birth['effective_config']))
            return owner,birth,hold,instance
        startup=self.session.commands.details(hold['actions']['start']['reference'])['details']['startup']
        owner=dict(fixture_id=birth['id'],container_id=birth['container_id'],hold_id=self.operation,
                   startup_sha256=fingerprint(startup),config_sha256=fingerprint(birth['effective_config']))
        return owner,birth,hold,startup

    def _unreleased(self, hold, birth):
        require(hold['phase']=='policy_disabled' and set(hold['actions'])=={'disable_restart','stop'}
                and hold['actions']['disable_restart']['phase']=='completed'
                and hold['actions']['stop']['phase']=='armed', 'only original never-released stop arm may retire')
        reference=hold['actions']['stop']['reference']
        original=self.session.commands._read(reference,historical=True)
        require(original['phase']=='armed' and original['outcome'] is None and original['details'] is None
                and 'native_dispatch_started' not in original and 'exit_progress' not in original
                and original['command']==hold['actions']['stop']['command']
                and birth['container_id']==hold['actor']['container_id']==self.session.profile['actor']['container_id'],
                'original unreleased command and canary required')
        return original

    def _retirement(self, hold, birth):
        row=self.journal.db.execute('SELECT * FROM image_build_arm_retirements WHERE hold_id=?',(self.operation,)).fetchone()
        require(row is not None, 'explicit unreleased-arm retirement required before disposal')
        value=json.loads(row['payload']);original=self._unreleased(hold,birth)
        fields(value,('id','hold_id','command_id','hold_sha256','command_sha256','profile_sha256',
                      'fixture_id','container_id','original_epoch_id','original_epoch_sha256'), 'original arm retirement')
        require(fingerprint(value)==row['fingerprint'] and value['id']==row['id']
                and value['hold_sha256']==fingerprint(hold) and value['command_sha256']==fingerprint(original)
                and value['profile_sha256']==fingerprint(self.session.profile) and value['fixture_id']==birth['id']
                and value['container_id']==birth['container_id'] and value['command_id']==row['command_id']==original['id']
                and value['original_epoch_id']==original['epoch_id'] and value['original_epoch_sha256']==original['epoch_sha256'],
                'original arm retirement lineage differs')
        return value

    def prepare_unreleased(self):
        """Atomic tombstone + separate disposal intent; old arm/hold stay intact."""
        with self.journal.execution_lock:
            self.session.runtime.check();hold=self.session.hold.read(self.operation);birth=self.fixture.get()
            require(birth is not None and birth['original']['config']['Labels'].get('io.dnlab.spike')=='image-build-hold'
                    and self.fixture.spec['container_name'].startswith('drsp-ibc-'), 'original disposable canary required')
            original=self._unreleased(hold,birth)
            previous=self.journal.db.execute('SELECT id FROM image_build_canary_cleanup WHERE container_id=?',(birth['container_id'],)).fetchone()
            if previous:return self._read(previous['id'])
            require(self.session.profile['policy']==POLICY, 'original canary policy profile required')
            current=self.fixture.bind_response(birth)
            qualify(current,container_id=birth['container_id'],name=self.fixture.spec['container_name'],
                    effective_config=birth['effective_config'],phase='running',restart_policy=NO_RESTART)
            snapshot=self.session.observation(hold)
            require(snapshot['actor']==self.session.profile['actor'] and snapshot['running'] is True
                    and snapshot['restart_policy']==NO_RESTART, 'original running disposal generation required')
            retirement=dict(id=uuid.uuid4().hex,hold_id=self.operation,command_id=original['id'],
                hold_sha256=fingerprint(hold),command_sha256=fingerprint(original),profile_sha256=fingerprint(self.session.profile),
                fixture_id=birth['id'],container_id=birth['container_id'],original_epoch_id=original['epoch_id'],
                original_epoch_sha256=original['epoch_sha256'])
            with self.journal.transaction():
                key='image-build-control:'+birth['container_id']
                row=self.journal.db.execute('SELECT * FROM resources WHERE key=?',(key,)).fetchone()
                require(row is not None and (row['lab'],row['node'],row['operation_id'])==
                        (self.fixture.request['lab_id'],'image-build',self.operation), 'original hold claim required for retirement')
                require(self._unreleased(self.session.hold.read(self.operation),self.fixture.get())==original,
                        'original arm changed before retirement')
                self.journal.db.execute('INSERT INTO image_build_arm_retirements VALUES(?,?,?,?,?)',
                    (retirement['id'],self.operation,original['id'],canonical(retirement),fingerprint(retirement)))
                owner,_,_,_=self._owner()
                value=dict(id=uuid.uuid4().hex,owner=owner,phase='policy_disabled',exit=None)
                self.journal.db.execute('UPDATE resources SET operation_id=? WHERE key=?',(value['id'],key))
                self._pre(value,'running',NO_RESTART)
                self.journal.db.execute('INSERT INTO image_build_canary_cleanup VALUES(?,?,?,?)',
                    (value['id'],birth['container_id'],canonical(value),fingerprint(value)))
            return deepcopy(value)

    def _read(self, operation):
        row=self.journal.db.execute('SELECT * FROM image_build_canary_cleanup WHERE id=?',(operation,)).fetchone()
        require(row is not None, 'original canary cleanup missing')
        value=json.loads(row['payload'])
        fields(value,('id','owner','phase','exit'),'canary cleanup intent')
        owner,_,_,_=self._owner()
        require(fingerprint(value)==row['fingerprint'] and value['id']==operation
                and value['owner']==owner and row['container_id']==owner['container_id']
                and value['phase'] in ('prepared','policy_requested','policy_disabled','term_requested',
                                       'pidfd_exited','exit_verified','remove_requested','removed'), 'original canary cleanup changed')
        require((value['exit'] is not None)==(value['phase'] in ('pidfd_exited','exit_verified','remove_requested','removed')),
                'original canary cleanup exit stage differs')
        if value['exit'] is not None:
            fields(value['exit'],('pidfd','logs','exit_code'),'original canary cleanup exit')
            proof=value['exit']
            ImageBuildCommands._exit_proof(proof['pidfd'])
            if value['phase']=='pidfd_exited':
                require(proof['logs'] is None and proof['exit_code'] is None, 'partial exit is not an ordinary shutdown receipt')
            else:
                require(proof['logs'].get('ordinary_shutdown_log_verified') is True
                        and proof['logs'].get('namespace_pid')==proof['pidfd']['namespace_pid']
                        and type(proof['exit_code']) is int and proof['exit_code'] in (0,143),
                        'original canary ordinary exit proof required')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE image_build_canary_cleanup SET payload=?,fingerprint=? WHERE id=?',
                                    (canonical(value),fingerprint(value),value['id']))

    def _claim(self, value):
        key='image-build-control:'+value['owner']['container_id']
        row=self.journal.db.execute('SELECT * FROM resources WHERE key=?',(key,)).fetchone()
        require(row is not None and (row['lab'],row['node'],row['operation_id'])==
                (self.fixture.request['lab_id'],'image-build',value['id']), 'original canary cleanup claim missing')

    def _pre(self, value, phase, restart):
        self._claim(value);owner,birth,hold,startup=self._owner()
        require(owner==value['owner'], 'original cleanup generation changed')
        current=self.fixture.bind_response(birth)
        qualify(current,container_id=owner['container_id'],name=self.fixture.spec['container_name'],
                effective_config=birth['effective_config'],phase=phase,restart_policy=restart)
        generation=startup['generation']
        require(current['State']['StartedAt']==generation['started_at']
                and current['RestartCount']==generation['restart_count'], 'original canary startup generation differs')
        if phase=='running':
            require(current['State']['Pid']==startup['capture']['process']['pid'], 'original canary PID differs')
            snapshot=self.session.observation(hold)
            require(snapshot['actor']==startup['actor'] and snapshot['running'] is True
                    and snapshot['restart_policy']==restart, 'original canary cleanup running snapshot differs')
        else:
            require(current['State']['Pid']==0 and current['State']['Running'] is False
                    and current['State']['ExitCode'] in (0,143), 'original canary exit differs')
            self.session.observation._conditions(hold,pid=None)
        return current

    def prepare(self):
        with self.journal.execution_lock:
            owner,_,_,_=self._owner()
            row=self.journal.db.execute('SELECT id FROM image_build_canary_cleanup WHERE container_id=?',(owner['container_id'],)).fetchone()
            if row:return self._read(row['id'])
            value=dict(id=uuid.uuid4().hex,owner=owner,phase='prepared',exit=None)
            with self.journal.transaction():
                key='image-build-control:'+owner['container_id']
                require(self.journal.db.execute('SELECT 1 FROM resources WHERE key=?',(key,)).fetchone() is None,
                        'canary already controlled by another operation')
                self.journal.db.execute('INSERT INTO resources VALUES(?,?,?,?)',
                    (key,self.fixture.request['lab_id'],'image-build',value['id']))
                self._pre(value,'running',POLICY)
                self.journal.db.execute('INSERT INTO image_build_canary_cleanup VALUES(?,?,?,?)',
                    (value['id'],owner['container_id'],canonical(value),fingerprint(value)))
            return deepcopy(value)

    def execute(self, operation):
        with self.journal.execution_lock:
            value=self._read(operation)
            if value['phase']=='removed':
                require(self.fixture.backend.docker.inspect(value['owner']['container_id']) is None
                        and self.fixture.backend.docker.inspect(self.fixture.spec['container_name']) is None,
                        'removed canary identity reappeared')
                return value
            self._claim(value)
            require(value['phase'] not in ('policy_requested','term_requested'),
                    'original canary cleanup command uncertain; no resend')
            if value['phase']=='prepared':
                self._pre(value,'running',POLICY);value['phase']='policy_requested';self._save(value)
                self._pre(value,'running',POLICY)
                self.session.executor.engine.update_policy(NO_RESTART)
                self._pre(value,'running',NO_RESTART);value['phase']='policy_disabled';self._save(value)
            if value['phase']=='policy_disabled':
                self._pre(value,'running',NO_RESTART)
                _,_,_,startup=self._owner();value['phase']='term_requested';self._save(value)
                self._pre(value,'running',NO_RESTART)
                with self.session.executor.term.pin(startup['capture'],value['owner']['container_id'],self.session.profile['copies']) as pinned:
                    def preflight():self._pre(value,'running',NO_RESTART);return True
                    proof=pinned.term(preflight=preflight)
                ImageBuildCommands._exit_proof(proof)
                value.update(phase='pidfd_exited',exit=dict(pidfd=proof,logs=None,exit_code=None));self._save(value)
            if value['phase']=='pidfd_exited':
                _,_,_,startup=self._owner();proof=value['exit']['pidfd']
                deadline=self.session.executor.clock()+10
                while True:
                    self._owner();self._claim(value)
                    current=self.fixture.bind_response(self.fixture.get())
                    if current['State']['Status']=='exited':break
                    require(self.session.executor.clock()<deadline, 'canary Docker exit uncertain; no resend')
                    self.session.executor.pause(0.05)
                current=self._pre(value,'exited',NO_RESTART)
                logs=self.session.executor.engine.shutdown_logs(startup['generation']['started_at'],proof['namespace_pid'])
                value.update(phase='exit_verified',exit=dict(pidfd=proof,logs=logs,exit_code=current['State']['ExitCode']))
                self._save(value);value=self._read(operation)
            if value['phase'] in ('exit_verified','remove_requested'):
                cid=value['owner']['container_id'];by_id=self.fixture.backend.docker.inspect(cid)
                by_name=self.fixture.backend.docker.inspect(self.fixture.spec['container_name'])
                if by_id is not None or by_name is not None:self._pre(value,'exited',NO_RESTART)
                value['phase']='remove_requested';self._save(value)
                if by_id is not None or by_name is not None:self._pre(value,'exited',NO_RESTART)
                docker=self.fixture.backend.docker;retirement=self
                class ExitedOnlyDocker:
                    def inspect(self, identity):return docker.inspect(identity)
                    def signal(self, *args, **kwargs):
                        require(False, 'canary cleanup refuses another signal after verified exit')
                    def remove(self, identity):
                        require(identity==cid, 'original canary removal ID required')
                        retirement._pre(value,'exited',NO_RESTART)
                        return docker.remove(identity)
                self.fixture.backend.docker=ExitedOnlyDocker()
                try:self.fixture.cleanup()
                finally:self.fixture.backend.docker=docker
                require(self.fixture.get()['phase']=='cleaned' and self.fixture.backend.docker.inspect(cid) is None
                        and self.fixture.backend.docker.inspect(self.fixture.spec['container_name']) is None,
                        'original canary absence not verified')
                value['phase']='removed'
                with self.journal.transaction():
                    self._claim(value)
                    self.journal.db.execute('UPDATE image_build_canary_cleanup SET payload=?,fingerprint=? WHERE id=?',
                                            (canonical(value),fingerprint(value),operation))
                    self.journal.db.execute('DELETE FROM resources WHERE key=? AND operation_id=?',
                                            ('image-build-control:'+cid,operation))
            return deepcopy(value)
