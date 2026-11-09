"""Explicit administrative window and tracked account provisioning contract.

The window is an agreement plus a rechecked provider receipt, not an OS barrier
against other root writers. The account helper is injected; no useradd/groupadd
or host account database is opened by this module.
"""
from copy import deepcopy
import json

from .manifest import Conflict, canonical, fingerprint


class ProvisioningWindow:
    def __init__(self, receipt, observe):
        if (not isinstance(receipt, dict) or set(receipt) != {'operation_id','context','targets','nonce'}
                or not receipt['operation_id'] or not isinstance(receipt['context'],dict)
                or not receipt['context'] or not isinstance(receipt['targets'],list)
                or not receipt['targets'] or len(set(receipt['targets'])) != len(receipt['targets'])
                or not isinstance(receipt['nonce'],str) or len(receipt['nonce']) != 32
                or not callable(observe)):
            raise Conflict('explicit provisioning window required')
        self.receipt, self.observe = deepcopy(receipt), observe
        self.sha256 = fingerprint(self.receipt)

    def verify(self, item, operation_id, expected=None):
        if (operation_id != self.receipt['operation_id'] or item['spec']['key'] not in self.receipt['targets']
                or expected is not None and expected != self.sha256
                or self.observe() != self.receipt):
            raise Conflict('original provisioning window is not active')
        return self.sha256


def account_marker(operation_id, nonce):
    """One GECOS-safe field; raw intent and nonce remain in the journal."""
    if not isinstance(operation_id,str) or not operation_id or not isinstance(nonce,str) or not nonce:
        raise Conflict('original account marker identity required')
    return 'dnlab-v1-' + fingerprint(dict(version=1,intent_id=operation_id,nonce=nonce))


def account_request(item, operation_id):
    spec = item['spec']
    if spec['kind']=='group':
        expected = {'name':spec['name'],'gid':spec['gid']}
    elif spec['kind']=='account':
        expected = {'name':spec['name'],'uid':spec['uid'],'gid':spec['gid'],'home':spec['home'],
                    'shell':'/usr/sbin/nologin','locked':True,
                    'comment':account_marker(operation_id,item['nonce'])}
    else:raise Conflict('account or group target required')
    if (not isinstance(expected['name'],str) or not expected['name'] or expected['gid']<=0
            or spec['kind']=='account' and (expected['uid']<=0 or spec.get('interactive_login') is not False)):
        raise Conflict('dedicated non-root account required')
    return dict(intent_id=operation_id,nonce=item['nonce'],spec_sha256=fingerprint(spec),
                kind=spec['kind'],expected=expected)


class InstallationAccounts:
    def __init__(self, journal, helper):
        self.journal,self.helper=journal,helper
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_install_account_births '
                '(operation_id TEXT NOT NULL,nonce TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(operation_id,nonce))')

    def _read(self,item,operation):
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM libvirt_install_account_births WHERE operation_id=? AND nonce=?',
                (operation,item['nonce'])).fetchone()
        if row is None:return None
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['request']!=account_request(item,operation)
                or value['phase'] not in ('create_requested','created')):
            raise Conflict('original account provisioning intent differs')
        return value

    def _save(self,item,operation,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_install_account_births SET payload=?,fingerprint=? '
                'WHERE operation_id=? AND nonce=?',(canonical(value),fingerprint(value),operation,item['nonce']))

    def _completed(self,value):
        # The helper must persist its own original completion before replying.
        # A matching account row alone never proves which command created it.
        receipt=self.helper.completion(deepcopy(value['request']))
        if (not isinstance(receipt,dict) or set(receipt)!={'request_sha256','exit_code','identity'}
                or receipt['request_sha256']!=fingerprint(value['request'])
                or type(receipt['exit_code']) is not int or receipt['exit_code']!=0
                or receipt['identity']!=value['request']['expected']):
            raise Conflict('original account helper completion is missing or differs')
        if self.helper.inspect(deepcopy(value['request']))!=receipt['identity']:
            raise Conflict('original account resource differs')
        return receipt

    def observe(self,item,operation):
        with self.journal.execution_lock:
            value=self._read(item,operation)
            if value is None:
                if self.helper.inspect(account_request(item,operation)) is None:return None
                raise Conflict('account name or numeric identity is already occupied')
            if value['phase']!='created':raise Conflict('account create uncertain; explicit recovery required')
            receipt=self._completed(value)
            if receipt!=value['completion']:raise Conflict('original account completion replaced')
            return dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
                        identity=deepcopy(receipt['identity']))

    def preflight_observe(self,item,operation,*,current_request_sha256,window_sha256):
        """Observe accounts without reentering helper completion/preflight."""
        request=account_request(item,operation)
        value=self._read(item,operation)
        identity=self.helper.inspect(deepcopy(request))
        if value is None:
            if identity is None:return None
            raise Conflict('untracked account target occupied during complete preflight')
        if value['window_sha256']!=window_sha256:
            raise Conflict('original account provisioning window differs')
        current=fingerprint(request)==current_request_sha256
        if value['phase']!='created' and not current:
            raise Conflict('another account operation remains pending')
        if identity is None and value['phase']!='created':return None
        completion=self.helper.preflight_completion(deepcopy(request))
        if (identity!=request['expected'] or completion is None
                or value['phase']=='created' and completion!=value['completion']):
            raise Conflict('original account birth/completion differs during complete preflight')
        return dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
                    identity=deepcopy(identity))

    def create(self,item,operation,*,window):
        with self.journal.execution_lock:
            window.verify(item,operation)
            if self._read(item,operation) is not None:raise Conflict('original account create held; use recovery')
            if self.observe(item,operation) is not None:raise Conflict('account target already occupied')
            value=dict(request=account_request(item,operation),phase='create_requested',
                       window_sha256=window.sha256,completion=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_install_account_births VALUES(?,?,?,?)',
                    (operation,item['nonce'],canonical(value),fingerprint(value)))
            window.verify(item,operation,value['window_sha256'])
            if self.helper.inspect(deepcopy(value['request'])) is not None:
                raise Conflict('account target changed before create')
            self.helper.create(deepcopy(value['request']))
            return self.recover(item,operation,window=window)

    def recover(self,item,operation,*,window):
        with self.journal.execution_lock:
            value=self._read(item,operation)
            if value is None:raise Conflict('original account provisioning intent missing')
            window.verify(item,operation,value['window_sha256'])
            receipt=self._completed(value)
            window.verify(item,operation,value['window_sha256'])
            value.update(phase='created',completion=receipt)
            self._save(item,operation,value)
            return self.observe(item,operation)
