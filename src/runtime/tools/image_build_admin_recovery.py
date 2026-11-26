"""Separate administrative retirement of a gate with an uncertain start.

Providers must pin the original producer and hold its kernel execution lock.
This operation restores policy on an explicitly qualified current generation;
it never turns the old uncertain start into a successful startup receipt.
No native action or process discovery has a default implementation.
"""
from copy import deepcopy
import json

from dnlab_runtime.image_build_hold import NO_RESTART, policy
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import digest, fields, require


class AdministrativeRecovery:
    def __init__(self, journal, *, preflight, terminate_owner, update_policy, retire_claim):
        require(all(callable(fn) for fn in (preflight,terminate_owner,update_policy,retire_claim)),
                'qualified administrative recovery providers required')
        self.journal,self.preflight,self.terminate_owner,self.update_policy,self.retire_claim=(
            journal,preflight,terminate_owner,update_policy,retire_claim)
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS image_build_admin_recoveries '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def _request(request):
        fields(request,('id','nonce','original_sha256','owner_sha256','service_sha256','restart_policy'),
               'separate administrative recovery request')
        require(all(type(request[key]) is str and len(request[key])==32
                    and all(c in '0123456789abcdef' for c in request[key]) for key in ('id','nonce'))
                and all(digest(request[key]) for key in ('original_sha256','owner_sha256','service_sha256')),
                'original administrative recovery identities required')
        policy(request['restart_policy'])
        require(request['restart_policy']==dict(Name='unless-stopped',MaximumRetryCount=0),
                'only explicit original image-build policy restoration supported')

    def _save(self, value, *, insert=False):
        with self.journal.transaction():
            if insert:
                self.journal.db.execute('INSERT INTO image_build_admin_recoveries VALUES(?,?,?)',
                    (value['request']['id'],canonical(value),fingerprint(value)))
            else:
                self.journal.db.execute('UPDATE image_build_admin_recoveries SET payload=?,fingerprint=? WHERE id=?',
                    (canonical(value),fingerprint(value),value['request']['id']))

    def read(self, operation):
        row=self.journal.db.execute('SELECT * FROM image_build_admin_recoveries WHERE id=?',(operation,)).fetchone()
        require(row is not None, 'original administrative recovery missing')
        value=json.loads(row['payload'])
        fields(value,('request','phase','owner_exit','retirement'),'administrative recovery state')
        self._request(value['request'])
        require(row['id']==operation==value['request']['id'] and fingerprint(value)==row['fingerprint']
                and value['phase'] in ('prepared','owner_term_requested','owner_exited','policy_requested',
                                       'policy_verified','completed'), 'administrative recovery journal differs')
        exited=value['phase'] in ('owner_exited','policy_requested','policy_verified','completed')
        require((value['owner_exit'] is not None)==exited
                and (value['retirement'] is not None)==(value['phase']=='completed'),
                'administrative recovery progress differs')
        if exited:self._exit(value['request'],value['owner_exit'])
        if value['phase']=='completed':self._retirement(value['request'],value['retirement'])
        return value

    @staticmethod
    def _exit(request, proof):
        require(proof==dict(owner_sha256=request['owner_sha256'],pidfd_exit_verified=True,
                           term_count=1,force_used=False), 'original single TERM owner exit required')
        require(proof['pidfd_exit_verified'] is True and type(proof['term_count']) is int
                and proof['force_used'] is False, 'typed original owner exit required')

    @staticmethod
    def _retirement(request, receipt):
        require(receipt==dict(original_sha256=request['original_sha256'],recovery_id=request['id'],
                claim_released=True,old_start_uncertain=True)
                and receipt['claim_released'] is True and receipt['old_start_uncertain'] is True,
                'separate retirement receipt required; old start remains uncertain')

    def _pre(self, request, *, owner_alive, restart):
        wanted=dict(original_sha256=request['original_sha256'],owner_sha256=request['owner_sha256'],
            service_sha256=request['service_sha256'],owner_alive=owner_alive,restart_policy=restart,
            execution_lock_held=True,no_native_dispatch=True,vm_resources_absent=True,window_active=True)
        observed=self.preflight(deepcopy(request),owner_alive=owner_alive,restart_policy=deepcopy(restart))
        require(observed==wanted and all(observed[key] is wanted[key] for key in
            ('owner_alive','execution_lock_held','no_native_dispatch','vm_resources_absent','window_active')),
            'qualified administrative recovery preflight differs')

    def prepare(self, request):
        with self.journal.execution_lock:
            self._request(request)
            row=self.journal.db.execute('SELECT id FROM image_build_admin_recoveries WHERE id=?',(request['id'],)).fetchone()
            if row:
                value=self.read(request['id'])
                require(value['request']==request, 'administrative recovery intent cannot be replaced')
                return value
            self._pre(request,owner_alive=True,restart=NO_RESTART)
            value=dict(request=deepcopy(request),phase='prepared',owner_exit=None,retirement=None)
            self._save(value,insert=True)
            return self.read(request['id'])

    def apply(self, operation):
        with self.journal.execution_lock:
            value=self.read(operation);request=value['request']
            require(value['phase']!='owner_term_requested', 'owner TERM uncertain; no resend or inferred exit')
            if value['phase']=='completed':return value
            if value['phase']=='prepared':
                self._pre(request,owner_alive=True,restart=NO_RESTART)
                value['phase']='owner_term_requested';self._save(value)
                check=lambda:self._pre(request,owner_alive=True,restart=NO_RESTART)
                check()
                proof=self.terminate_owner(deepcopy(request),check=check)
                self._exit(request,proof)
                value.update(phase='owner_exited',owner_exit=deepcopy(proof));self._save(value)
            if value['phase']=='owner_exited':
                self._pre(request,owner_alive=False,restart=NO_RESTART)
                value['phase']='policy_requested';self._save(value)
                self._pre(request,owner_alive=False,restart=NO_RESTART)
                self.update_policy(deepcopy(request['restart_policy']))
            if value['phase']=='policy_requested':
                # Lost policy response permits observation only, never resend.
                self._pre(request,owner_alive=False,restart=request['restart_policy'])
                value['phase']='policy_verified';self._save(value)
            if value['phase']=='policy_verified':
                self._pre(request,owner_alive=False,restart=request['restart_policy'])
                receipt=self.retire_claim(deepcopy(request),deepcopy(value['owner_exit']))
                self._retirement(request,receipt)
                value.update(phase='completed',retirement=deepcopy(receipt));self._save(value)
            return self.read(operation)
