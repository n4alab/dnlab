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
        require(hold['phase']=='restored' and birth is not None
                and birth['original']['config']['Labels'].get('io.dnlab.spike')=='image-build-hold'
                and self.fixture.spec['container_name'].startswith('drsp-ibc-')
                and birth['container_id']==hold['actor']['container_id']==self.session.executor.engine.container_id,
                'original restored disposable image-build canary required')
        startup=self.session.commands.details(hold['actions']['start']['reference'])['details']['startup']
        owner=dict(fixture_id=birth['id'],container_id=birth['container_id'],hold_id=self.operation,
                   startup_sha256=fingerprint(startup),config_sha256=fingerprint(birth['effective_config']))
        return owner,birth,hold,startup

    def _read(self, operation):
        row=self.journal.db.execute('SELECT * FROM image_build_canary_cleanup WHERE id=?',(operation,)).fetchone()
        require(row is not None, 'original canary cleanup missing')
        value=json.loads(row['payload'])
        fields(value,('id','owner','phase','exit'),'canary cleanup intent')
        owner,_,_,_=self._owner()
        require(fingerprint(value)==row['fingerprint'] and value['id']==operation
                and value['owner']==owner and row['container_id']==owner['container_id']
                and value['phase'] in ('prepared','policy_requested','policy_disabled','term_requested',
                                       'exit_verified','remove_requested','removed'), 'original canary cleanup changed')
        require((value['exit'] is not None)==(value['phase'] in ('exit_verified','remove_requested','removed')),
                'original canary cleanup exit stage differs')
        if value['exit'] is not None:
            fields(value['exit'],('pidfd','logs','exit_code'),'original canary cleanup exit')
            proof=value['exit']
            require(proof['pidfd'].get('pidfd_exit_verified') is True and proof['pidfd'].get('term_count')==1
                    and proof['pidfd'].get('force_used') is False
                    and proof['logs'].get('ordinary_shutdown_log_verified') is True
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
                _,_,_,startup=self._owner();value['phase']='term_requested';self._save(value)
                self._pre(value,'running',NO_RESTART)
                with self.session.executor.term.pin(startup['capture'],value['owner']['container_id'],self.session.profile['copies']) as pinned:
                    def preflight():self._pre(value,'running',NO_RESTART);return True
                    proof=pinned.term(preflight=preflight)
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
