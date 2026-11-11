"""Explicit unit exchange and original backup, qualified on temporary files only.

No service commands. Full inactive-session observation and the administrative
window are mandatory. There is no fallback for unsupported renameat2 flags and
no repeated uncertain rename. The caller retains the original staging request.
"""
from copy import deepcopy
import ctypes
import json
import os

from .libvirt_configuration import UNIT
from .manifest import Conflict,canonical,fingerprint

EXCHANGE=2
NOREPLACE=1


def rename_siblings(parent,source,target,flags):
    if flags not in (EXCHANGE,NOREPLACE):raise Conflict('explicit rename semantics required')
    for name in (source,target):
        if not isinstance(name,str) or not name or name in ('.','..') or '/' in name or '\0' in name:
            raise Conflict('sibling rename names required')
    library=ctypes.CDLL(None,use_errno=True)
    try:call=library.renameat2
    except AttributeError:raise Conflict('renameat2 unavailable; no fallback') from None
    call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    call.restype=ctypes.c_int
    if call(parent,os.fsencode(source),parent,os.fsencode(target),flags)!=0:
        error=ctypes.get_errno()
        raise OSError(error,os.strerror(error))


class ConfigurationSwap:
    def __init__(self,staging,*,preflight=None,readonly=False):
        if not readonly and not callable(preflight):raise Conflict('complete inactive swap preflight required')
        self.staging,self.preflight=staging,preflight
        self.journal,self.files,self.window=staging.journal,staging.files,staging.window
        self.readonly=readonly
        if readonly:return
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_configuration_swaps '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _read(self,value):
        row=self.journal.db.execute('SELECT * FROM libvirt_configuration_swaps WHERE id=?',(value['id'],)).fetchone()
        if row is None:return None
        record=json.loads(row['payload'])
        if (fingerprint(record)!=row['fingerprint'] or record['revision']!=value
                or record['phase'] not in ('exchange_requested','exchanged','backup_requested','completed')):
            raise Conflict('original configuration exchange intent differs')
        stage=self.staging._read(value)
        if stage is None or stage['phase']!='staged' or record['candidate_proof']!=stage['proof']:
            raise Conflict('original configuration candidate binding differs')
        return record

    def _save(self,record,phase):
        record['phase']=phase
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_configuration_swaps SET payload=?,fingerprint=? WHERE id=?',
                (canonical(record),fingerprint(record),record['revision']['id']))

    def _check(self,value,*,window=True):
        if self.readonly:raise Conflict('readonly configuration swap')
        # Staging already bound all paths, profile and window. Re-read its exact
        # immutable request, without requiring the source at its old leaf.
        stage=self.staging._read(value)
        if stage is None or stage['phase']!='staged':raise Conflict('original completed staging required')
        prefix='/etc/systemd/system/.dnlab-libvirtd.'+value['nonce']
        if (value['staging']!=prefix+'.candidate' or value['backup']!=prefix+'.previous'
                or value['plan']['source_item']['spec']['path']!=UNIT
                or value['plan']['target_spec']['path']!=UNIT
                or self.window.sha256!=value['window_sha256']):
            raise Conflict('original exchange path/window binding differs')
        target=dict(spec=value['plan']['target_spec'])
        if window:self.window.verify(target,value['id'],value['window_sha256'])
        expected=dict(revision_sha256=fingerprint(value),unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)
        if self.preflight(deepcopy(value))!=expected:raise Conflict('complete inactive exchange preflight differs')
        if window:self.window.verify(target,value['id'],value['window_sha256'])
        return stage

    def _locations(self,value,layout):
        stage=self.staging._read(value)
        source=value['plan']['source_item'];candidate=stage['item']
        old_path=UNIT if layout=='original' else value['staging'] if layout=='exchanged' else value['backup']
        new_path=value['staging'] if layout=='original' else UNIT
        old=self.files.observe_relocated(source,value['installation']['id'],old_path)
        new=self.files.observe_relocated(candidate,value['id'],new_path)
        if old!=source['proof'] or new!=stage['proof']:raise Conflict('original exchange file identities differ')
        absent=value['staging'] if layout=='backed_up' else value['backup']
        with self.files._parent(absent) as (parent,name):
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise Conflict('exchange destination occupied; preserve foreign file')
        return old,new

    def _sync(self,value,layout):
        old,new=self._locations(value,layout)
        paths=(value['staging'] if layout=='exchanged' else value['backup'],UNIT)
        for path,proof in zip(paths,(old,new)):
            with self.files._parent(path) as (parent,name):
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
                try:
                    if self.files._kernel_id(fd)!={key:proof['identity'][key] for key in ('device','inode')}:
                        raise Conflict('exchange file replaced before sync')
                    os.fsync(fd);os.fsync(parent)
                finally:os.close(fd)
        self._locations(value,layout)

    def _rename(self,value,source,target,flags):
        self._check(value)
        with self.files._parent(UNIT) as (parent,_):
            # Each original birth pins this same directory, including its visible
            # path. The exclusive administrative window excludes other writers.
            self._locations(value,'original' if flags==EXCHANGE else 'exchanged')
            rename_siblings(parent,source.rsplit('/',1)[1],target.rsplit('/',1)[1],flags)

    def execute(self,value):
        with self.journal.execution_lock:
            self._check(value)
            record=self._read(value)
            if record is not None:
                if record['phase']!='completed':raise Conflict('exchange pending; explicit recovery required')
                return self.observe(value)
            stage=self.staging.observe(value)
            self._locations(value,'original')
            record=dict(revision=deepcopy(value),candidate_proof=stage,phase='exchange_requested')
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_configuration_swaps VALUES(?,?,?)',
                    (value['id'],canonical(record),fingerprint(record)))
            self._rename(value,UNIT,value['staging'],EXCHANGE)
            self._check(value);self._sync(value,'exchanged')
            self._save(record,'exchanged')
            return self._backup(value,record)

    def _backup(self,value,record):
        self._check(value);self._locations(value,'exchanged')
        self._save(record,'backup_requested')
        self._rename(value,value['staging'],value['backup'],NOREPLACE)
        self._check(value);self._sync(value,'backed_up')
        self._save(record,'completed')
        return self.observe(value)

    def recover(self,value):
        with self.journal.execution_lock:
            self._check(value)
            record=self._read(value)
            if record is None:raise Conflict('original exchange intent missing; no rename on recovery')
            phase=record['phase']
            if phase=='completed':return self.observe(value)
            if phase=='exchange_requested':
                # Only the original swapped arrangement proves that the uncertain
                # exchange happened. The original arrangement never permits retry.
                self._sync(value,'exchanged')
                self._save(record,'exchanged')
            elif phase=='backup_requested':
                self._sync(value,'backed_up')
                self._save(record,'completed')
                return self.observe(value)
            return self._backup(value,record)

    def observe(self,value):
        with self.journal.execution_lock:
            self._check(value,window=False)
            record=self._read(value)
            if record is None or record['phase']!='completed':raise Conflict('original exchange completion pending')
            old,new=self._locations(value,'backed_up')
            return dict(operation_id=value['id'],nonce=value['nonce'],source_proof=old,
                backup=dict(path=value['backup'],identity=old['identity']),
                replacement=dict(intent_id=value['id'],nonce=value['nonce'],
                    spec_sha256=fingerprint(value['plan']['target_spec']),identity=new['identity']))
