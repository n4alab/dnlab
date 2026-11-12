"""Journaled owner/group/persistence on the original creator's TAP descriptor.

The descriptor stays attached, with no bridge/IP or QEMU handoff. A lost lease
cannot be replaced from a matching interface. Release only removes persistence
on this same descriptor; explicit post-close observation confirms absence.
"""
from copy import deepcopy
import json

from .manifest import Conflict,canonical,fingerprint,identifier
from .vm_tap_device import EphemeralTap
from .vm_template import require

TUNSETPERSIST, TUNSETOWNER, TUNSETGROUP = 0x400454cb, 0x400454cc, 0x400454ce
PERSIST = 0x0800
COMMANDS = (TUNSETOWNER,TUNSETGROUP,TUNSETPERSIST)


class RetainedTapDevice(EphemeralTap):
    def _accepted_flags(self):
        base = super()._accepted_flags()
        return base | {value | PERSIST for value in base}

    def _change(self, command, target):
        require(command in COMMANDS and type(target) is int
            and (target in (0,1) if command == TUNSETPERSIST else 0 < target < 2**32-1),
            'explicit qualified TAP owner/group/persistence operation required')
        require(self._birth_proof is not None, 'original creator TAP acknowledgement required')
        self._iff()
        self.ioctl(self._fd, command, target)


def signature(proof):
    result = deepcopy(proof);result['flags'] &= ~PERSIST
    data = result['link']['linkinfo'].get('info_data',{})
    for key in ('user','group','persist'):data.pop(key,None)
    return result


def ownership(proof):
    data = proof['link']['linkinfo'].get('info_data',{})
    values = [data.get('user',-1), data.get('group',-1), int(bool(proof['flags'] & PERSIST))]
    require(all(type(value) is int and -1 <= value < 2**32-1 for value in values),
            'numeric original TAP owner/group required')
    if 'persist' in data:
        require(type(data['persist']) is bool and data['persist'] == bool(values[2]),
                'TAP persistence observations disagree')
    return values


def request_part(value):
    return {key:value[key] for key in ('id','spec','context','lease_token','birth','uid','gid')}


class TapRetention:
    def __init__(self, journal, device, *, preflight):
        require(isinstance(device,RetainedTapDevice) and callable(preflight),
                'original retained TAP device and complete preflight required')
        self.journal,self.device,self.preflight = journal,device,preflight
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_retention_intents '
                '(id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,ifname TEXT UNIQUE NOT NULL, '
                'ifindex INTEGER UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_tap_retention_intents WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original TAP retention intent missing')
        value = json.loads(row['payload'])
        if (fingerprint(value) != row['fingerprint'] or value['id'] != operation
                or value['spec']['nonce'] != row['nonce'] or value['spec']['name'] != row['ifname']
                or value['spec']['ifindex'] != row['ifindex']
                or fingerprint(request_part(value)) != value['request_sha256']
                or value['phase'] not in ('prepared','requested','retained','release_requested','released','absent')
                or type(value['step']) is not int or not 0 <= value['step'] <= 3
                or (value['phase'] in ('retained','release_requested','released','absent') and value['step'] != 3)
                or (value['phase'] in ('prepared','requested') and value['step'] == 3)):
            raise Conflict('original TAP retention journal differs')
        if value['step'] == 3:
            retained = value['retained_proof']
            require(retained is not None and signature(retained) == signature(value['birth'])
                and ownership(retained) == [value['uid'],value['gid'],1], 'original retained TAP receipt differs')
        elif value['retained_proof'] is not None:raise Conflict('unexpected early retained TAP receipt')
        if value['phase'] == 'absent':
            expected = dict(request_sha256=value['request_sha256'],original_fd_closed=True,absence_verified=True)
            if value['proof'] != expected:raise Conflict('original TAP absence receipt differs')
        elif value['proof'] is not None:raise Conflict('unexpected early TAP absence receipt')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_tap_retention_intents SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    def _bound(self, value, held):
        if held and self.read(value['id']) != value:raise Conflict('original TAP retention intent changed')

    def _source(self, value, *, held=True):
        self._bound(value,held)
        if (value['spec'] != self.device.spec or value['context'] != self.device.context
                or value['lease_token'] != self.device._lease_token
                or value['birth'] != self.device._birth_proof):
            raise Conflict('original TAP creator lease lost or changed; no adoption')
        self.device._scope()
        observed = self.preflight(deepcopy(value))
        require(observed == dict(request_sha256=value['request_sha256'],lease_token=value['lease_token'],
            original_birth_sha256=fingerprint(value['birth']),resources_verified=True,guest_writers_absent=True),
            'complete original TAP retention preflight required')
        self._bound(value,held);self.device._scope()

    def _observe(self, value, *, held=True):
        self._source(value,held=held);proof = self.device.capture()
        if signature(proof) != signature(value['birth']):raise Conflict('original TAP kernel configuration changed')
        initial = ownership(value['birth']);targets = [value['uid'],value['gid'],1]
        before = initial[:]
        for index in range(value['step']):before[index] = targets[index]
        allowed = [before]
        if value['phase'] == 'requested':
            after = before[:];after[value['step']] = targets[value['step']];allowed.append(after)
        elif value['phase'] in ('released','absent'):allowed = [[value['uid'],value['gid'],0]]
        elif value['phase'] == 'release_requested':allowed.append([value['uid'],value['gid'],0])
        if ownership(proof) not in allowed:raise Conflict('TAP ownership/persistence differs from original step')
        self._source(value,held=held)
        again = self.device.capture()
        if again != proof:raise Conflict('original TAP changed during retention preflight')
        return proof

    def prepare(self, operation, *, birth, uid, gid):
        identifier(operation,'TAP retention operation_id')
        require(type(uid) is int and type(gid) is int and 0 < uid < 2**32-1 and 0 < gid < 2**32-1,
                'explicit non-root QEMU UID/GID required')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_tap_retention_intents '
                'WHERE id=? OR nonce=? OR ifname=? OR ifindex=?',
                (operation,self.device.spec['nonce'],self.device.spec['name'],self.device.spec['ifindex'])).fetchone()
            if row:
                saved = self.read(row['id'])
                if saved['id'] != operation or saved['birth'] != birth or (saved['uid'],saved['gid']) != (uid,gid):
                    raise Conflict('original TAP retention request differs')
                if saved['phase'] == 'absent':self.confirm_absent(operation)
                else:self._observe(saved)
                return saved
            require(birth == self.device._birth_proof and ownership(birth)[2] == 0,
                    'original unretained TAP creation receipt required')
            value = dict(id=operation,spec=deepcopy(self.device.spec),context=deepcopy(self.device.context),
                lease_token=self.device._lease_token,birth=deepcopy(birth),uid=uid,gid=gid,
                phase='prepared',step=0,proof=None,retained_proof=None)
            value['request_sha256'] = fingerprint(request_part(value));self._observe(value,held=False)
            with self.journal.transaction():
                self._observe(value,held=False)
                self.journal.db.execute('INSERT INTO vm_tap_retention_intents VALUES(?,?,?,?,?,?)',
                    (operation,self.device.spec['nonce'],self.device.spec['name'],self.device.spec['ifindex'],
                        canonical(value),fingerprint(value)))
            return self.read(operation)

    def _advance(self, value, proof):
        with self.journal.transaction():
            self._source(value)
            value['step'] += 1;value['phase'] = 'retained' if value['step'] == 3 else 'prepared'
            if value['step'] == 3:value['retained_proof'] = deepcopy(proof)
            self._save(value);self._observe(value)

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] in ('release_requested','released','absent'):raise Conflict('TAP retention already releasing')
            while value['phase'] != 'retained':
                proof = self._observe(value);step = value['step'];target = [value['uid'],value['gid'],1][step]
                if value['phase'] == 'requested':
                    if ownership(proof)[step] != target:raise Conflict('original TAP change is uncertain; no resend')
                    self._advance(value,proof);continue
                with self.journal.transaction():
                    self._source(value)
                    value['phase'] = 'requested';self._save(value)
                self._observe(value)
                self.device._change(COMMANDS[step],target)
                proof = self._observe(value)
                if ownership(proof)[step] != target:raise Conflict('original TAP change not confirmed')
                self._advance(value,proof)
            self._observe(value);return self.read(operation)

    def release(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] == 'absent':return self.confirm_absent(operation)
            if value['phase'] not in ('retained','release_requested','released'):
                raise Conflict('original retained TAP required before persistence release')
            proof = self._observe(value)
            if value['phase'] == 'retained':
                with self.journal.transaction():
                    self._source(value);value['phase'] = 'release_requested';self._save(value)
                self._observe(value);self.device._change(TUNSETPERSIST,0);proof = self._observe(value)
            elif value['phase'] == 'release_requested' and ownership(proof)[2] != 0:
                raise Conflict('original TAP persistence release uncertain; no resend')
            require(ownership(proof)[2] == 0,'original TAP persistence still enabled')
            with self.journal.transaction():
                self._source(value);value['phase'] = 'released';self._save(value);self._observe(value)
            return self.read(operation)

    def confirm_absent(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            if value['phase'] not in ('released','absent') or self.device._fd is not None:
                raise Conflict('original unretained TAP FD must be closed before absence confirmation')
            self._source(value)
            if self.device._links():raise Conflict('original TAP name/index absence not verified')
            proof = dict(request_sha256=value['request_sha256'],original_fd_closed=True,absence_verified=True)
            if value['phase'] == 'absent':return value
            with self.journal.transaction():
                self._source(value)
                if self.device._links():raise Conflict('TAP reappeared before absence commit')
                value.update(phase='absent',proof=proof)
                self._save(value)
                self._source(value)
                if self.device._links():raise Conflict('TAP reappeared during absence commit')
            return self.read(operation)
