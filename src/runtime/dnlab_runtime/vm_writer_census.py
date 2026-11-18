"""Readonly dedicated-session process census and original guest writer proofs.

Credentials select candidates, never establish ownership. Daemon observations
must come from original qualified service receipts; QEMU references come only
from this journal's boot receipts. This is not a scan for arbitrary host file
descriptors: exclusive runtime/storage ownership remains a separate preflight.
"""
from contextlib import ExitStack
from copy import deepcopy
import os

from .libvirt_account_process import AccountWorkerObserver
from .libvirt_observer import LibvirtDomainObserver
from .manifest import Conflict, fingerprint
from .qemu_process import PinnedQEMUProcess, validate_process_record
from .procfs_context import check as check_procfs
from .vm_template import digest, fields, require

UNITS = ('dnlab-virtlogd.service','dnlab-virtlockd.service','dnlab-libvirtd.service')
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def credentials(raw):
    values = {}
    for line in raw.splitlines():
        key,sep,value = line.partition(b':')
        if sep and key in (b'Uid',b'Gid',b'Groups'):
            if key in values:raise Conflict('duplicate session census credentials')
            try:values[key] = [int(v) for v in value.split()]
            except ValueError as error:raise Conflict('malformed session census credentials') from error
    require(set(values)=={b'Uid',b'Gid',b'Groups'} and len(values[b'Uid'])==len(values[b'Gid'])==4
            and all(v>=0 for row in values.values() for v in row), 'complete session census credentials required')
    return dict(uids=values[b'Uid'],gids=values[b'Gid'],groups=values[b'Groups'])


class DedicatedProcessInventory:
    def __init__(self, *, uid, gid, context, read_context, proc_identity, proc_root='/proc'):
        require(all(type(v) is int and v>0 for v in (uid,gid)) and callable(read_context),
                'dedicated credentials and context reader required')
        fields(context,('host_id','boot_id','namespaces'),'session census context')
        fields(context['namespaces'],('pid','mnt','net','user'),'session census namespaces')
        for value in context['namespaces'].values():
            fields(value,('device','inode'),'session census namespace')
            require(all(type(v) is int and v>0 for v in value.values()), 'original session namespace required')
        fields(proc_identity,('device','inode'),'qualified procfs identity')
        require(all(type(v) is int and v>0 for v in proc_identity.values()), 'qualified procfs identity required')
        self.uid,self.gid,self.context,self.read_context = uid,gid,deepcopy(context),read_context
        self.proc_identity,self.proc_root = deepcopy(proc_identity),proc_root

    def _check(self, proc):
        check_procfs(proc,context=self.context,read_context=self.read_context,
                     proc_identity=self.proc_identity,proc_root=self.proc_root)

    def __call__(self):
        with ExitStack() as stack:
            proc = os.open(self.proc_root,DIRECTORY);stack.callback(os.close,proc)
            self._check(proc);names = os.listdir(proc)
            require(len(names)<=65536, 'bounded session process inventory required')
            result = []
            for name in sorted(names):
                if not name.isascii() or not name.isdecimal() or not 0<int(name)<2**31:continue
                try:
                    root = os.open(name,DIRECTORY,dir_fd=proc)
                except FileNotFoundError:continue
                try:
                    try:value = credentials(AccountWorkerObserver._read_file(root,'status',65536))
                    except FileNotFoundError:continue
                    if self.uid not in value['uids'] and self.gid not in value['gids']+value['groups']:continue
                    original = os.fstat(root);visible = os.stat(name,dir_fd=proc,follow_symlinks=False)
                    require((original.st_dev,original.st_ino)==(visible.st_dev,visible.st_ino),
                            'session candidate proc directory replaced')
                    result.append(dict(pid=int(name),**value))
                finally:os.close(root)
            self._check(proc)
            return result


class SessionWriterCensus:
    def __init__(self, definitions, *, inventory, services, observe_services, observer=None):
        require(all(callable(fn) for fn in (inventory,observe_services)), 'qualified session census providers required')
        fields(services,UNITS,'original dedicated service processes')
        self.definitions,self.journal = definitions,definitions.journal
        self.inventory,self.services,self.observe_services = inventory,deepcopy(services),observe_services
        self.services_sha256 = fingerprint(services)
        self.observer = observer or self._observer
        require(callable(self.observer), 'original QEMU observer factory required')
        self._services()

    def _observer(self, reference, record):
        return LibvirtDomainObserver(self.definitions.connection,reference,xml_inactive_flag=2,
                                     process=PinnedQEMUProcess(record))

    def _services(self):
        require(fingerprint(self.services)==self.services_sha256 and self.observe_services()==self.services,
                'original dedicated service generations changed')
        session = self.definitions.session.profile;result = {}
        boot = self.definitions.session.proof()['daemon']['boot_id']
        for value in self.services.values():
            fields(value,('pid','start_ticks','boot_id','namespaces','pidfd_alive','uids','gids','groups',
                          'executable_sha256','argv','environment'),'original dedicated service observation')
            fields(value['namespaces'],('pid','mnt','net','user'),'original service namespaces')
            for namespace in value['namespaces'].values():
                fields(namespace,('device','inode'),'original service namespace')
                require(all(type(v) is int and v>0 for v in namespace.values()), 'original service namespace required')
            require(type(value['pid']) is int and value['pid']>0 and type(value['start_ticks']) is int
                    and value['start_ticks']>0 and value['boot_id']==boot and value['pidfd_alive'] is True
                    and value['uids']==[session['uid']]*4 and value['gids']==[session['gid']]*4
                    and type(value['groups']) is list and all(type(v) is int and v>=0 for v in value['groups'])
                    and digest(value['executable_sha256']) and value['pid'] not in result,
                    'original unique dedicated service process required')
            result[value['pid']] = {key:deepcopy(value[key]) for key in ('pid','uids','gids','groups')}
        return result

    def _inventory(self):
        if isinstance(self.inventory,DedicatedProcessInventory):
            session = self.definitions.session.profile
            require((self.inventory.uid,self.inventory.gid)==(session['uid'],session['gid'])
                    and self.inventory.context['host_id']==session['host_id']
                    and self.inventory.context['boot_id']==self.definitions.session.proof()['daemon']['boot_id']
                    and all(value['namespaces']==self.inventory.context['namespaces'] for value in self.services.values()),
                    'native session inventory profile differs')
        return self.inventory()

    def _definitions(self):
        values = {}
        for row in self.journal.db.execute('SELECT id FROM vm_definition_intents ORDER BY id'):
            value = self.definitions.read(row['id'])
            if value['birth']['host_id']==self.definitions.session.profile['host_id']:values[row['id']] = value
        return values

    def __call__(self, storage):
        with self.journal.execution_lock:
            values = self._definitions();operation = storage['id']
            require(operation in values and storage['birth']==values[operation]['birth']
                    and storage['definition_sha256']==values[operation]['request_fingerprint'],
                    'original VM owner required for writer census')
            self.definitions._session(values[operation])
            services = self._services();first = self._inventory()
            require(type(first) is list and len(first)<=65536, 'bounded dedicated session process list required')
            candidates = {}
            for item in first:
                fields(item,('pid','uids','gids','groups'),'session census process')
                require(type(item['pid']) is int and item['pid']>0 and item['pid'] not in candidates,
                        'unique session census PID required')
                candidates[item['pid']] = item
            require(all(candidates.get(pid)==value for pid,value in services.items()),
                    'original dedicated daemon missing or credentials changed')
            qemu = {};writers = [];observers = []
            for value in values.values():
                boot = value.get('boot')
                if not boot:continue
                if boot.get('process_record') is None:
                    require(boot.get('phase') in ('prepared','arming_requested','armed'),
                            'uncertain QEMU creation requires original boot recovery')
                    continue
                record = validate_process_record(boot['process_record']);reference = boot.get('reference')
                session = self.definitions.session.profile
                require(record['birth']==value['birth'] and record['uid']==session['uid']
                        and record['gid']==session['gid'] and record['process']['pid'] not in services
                        and record['process']['pid'] not in qemu and isinstance(reference,dict)
                        and reference.get('birth')==record['birth']
                        and reference.get('uri')==session['uri']
                        and boot.get('phase') in ('paused','activation_requested','monitored_paused','resume_requested','running')
                        and reference.get('process_sha256')==fingerprint(record['process']),
                        'original unique QEMU writer receipt required')
                pid = record['process']['pid'];candidate = candidates.get(pid)
                require(candidate is not None and candidate['uids']==[record['uid']]*4
                        and candidate['gids']==[record['gid']]*4, 'original QEMU writer missing or credentials changed')
                observe = self.observer(deepcopy(reference),deepcopy(record))
                observed = observe(deepcopy(value['birth']))
                require(observed['birth']==value['birth'] and observed['process']==record['process'],
                        'original QEMU writer observation differs')
                qemu[pid] = record
                observers.append((observe,deepcopy(value['birth']),deepcopy(observed)))
                if value['birth']['creator_operation_id']==operation:writers.append(deepcopy(record))
            require(set(candidates)==set(services)|set(qemu), 'unqualified process in dedicated libvirt session')
            require(self._inventory()==first, 'dedicated session processes changed during writer census')
            for observe,birth,proof in observers:
                require(observe(birth)==proof, 'QEMU writer changed during session census')
            self._services();self.definitions._session(values[operation])
            require(self._definitions()==values, 'VM generation changed during writer census')
            return writers
