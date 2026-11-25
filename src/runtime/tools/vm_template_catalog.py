"""Open an original quiescent template catalog without writes or initialization.

Physical bindings and the original store birth are explicit inputs. The caller
qualifies current context/source provenance. The exclusive readonly lock is
held for the lifetime of the capability; no SQLite sidecars are permitted.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import threading
from types import SimpleNamespace

from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.readonly_resource_journal import readonly_resource_journal
from dnlab_runtime.vm_bundle import metadata
from dnlab_runtime.vm_template_files import identity
from dnlab_runtime.vm_template_install import TemplateBundleInstall

LIMIT = 16 * 1024 * 1024


def stamp(info):return (*metadata(info),info.st_nlink)


class ReadonlyTemplateCatalog(TemplateBundleInstall):
    def read(self, operation):
        self.check()
        result = super().read(operation)
        self.check()
        return result

    def observe(self, operation):
        self.check()
        result = super().observe(operation)
        self.check()
        return result

    def prepare(self, *args, **kwargs):raise Conflict('readonly original template catalog')
    def apply(self, *args, **kwargs):raise Conflict('readonly original template catalog')
    def recover(self, *args, **kwargs):raise Conflict('readonly original template catalog')


@contextmanager
def open_catalog(binding, *, store_item, store_operation, store_proof, import_window, verify):
    """Yield a capability which expires on context exit; never create a lock."""
    binding,store_item,store_proof,import_window = deepcopy((binding,store_item,store_proof,import_window))
    if (not isinstance(binding,dict) or set(binding) != {'directory','identity','directory_identity','database_identity','lock_identity'}
            or not callable(verify) or not isinstance(binding['identity'],str) or len(binding['identity']) != 32
            or any(c not in '0123456789abcdef' for c in binding['identity'])):
        raise Conflict('explicit original readonly catalog binding required')
    directory = Path(binding['directory'])
    if not directory.is_absolute() or '..' in directory.parts or str(directory) != binding['directory']:
        raise Conflict('canonical original catalog directory required')
    if (store_item['spec']['kind'] != 'directory' or store_item['spec']['uid'] != 0
            or store_item['spec']['gid'] != 0 or store_item['spec']['mode'] != 0o755):
        raise Conflict('original root:root0755 template store birth required')
    with ExitStack() as stack:
        verify()
        parent = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);stack.callback(os.close,parent)
        for part in directory.parts[1:]:
            parent = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            stack.callback(os.close,parent)
        info = os.fstat(parent)
        if identity(info) != binding['directory_identity'] or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise Conflict('original private template catalog directory differs')
        directory_stamp = stamp(info)

        def regular(name, expected):
            pin = os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,pin)
            info = os.fstat(pin)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or identity(info) != expected):
                raise Conflict('original catalog '+name+' metadata differs')
            fd = os.open('/proc/self/fd/'+str(pin),os.O_RDONLY|os.O_CLOEXEC|os.O_NONBLOCK)
            stack.callback(os.close,fd)
            if stamp(os.fstat(fd)) != stamp(info):raise Conflict('catalog file changed while pinning')
            return fd,stamp(info)

        lock,lock_stamp = regular('workload.lock',binding['lock_identity'])
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Conflict('original template catalog is in use') from None
        database,database_stamp = regular('journal.sqlite3',binding['database_identity'])
        if not 0 < os.fstat(database).st_size <= LIMIT:raise Conflict('bounded original catalog required')

        def physical():
            verify()
            if (stamp(os.fstat(parent)) != directory_stamp
                    or stamp(os.stat(directory,follow_symlinks=False)) != directory_stamp
                    or stamp(os.fstat(database)) != database_stamp
                    or stamp(os.stat('journal.sqlite3',dir_fd=parent,follow_symlinks=False)) != database_stamp
                    or stamp(os.fstat(lock)) != lock_stamp
                    or stamp(os.stat('workload.lock',dir_fd=parent,follow_symlinks=False)) != lock_stamp):
                raise Conflict('original template catalog changed during observation')
            for name in ('journal.sqlite3-wal','journal.sqlite3-shm','journal.sqlite3-journal'):
                try:os.stat(name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:continue
                raise Conflict('original template catalog has pending SQLite state')

        physical()
        db = sqlite3.connect('file:/proc/self/fd/'+str(database)+'?mode=ro&immutable=1',uri=True,isolation_level=None)
        stack.callback(db.close)
        db.row_factory = sqlite3.Row;db.execute('PRAGMA query_only=ON')
        journal = SimpleNamespace(db=db,identity=binding['identity'],lock=threading.RLock(),
                                  execution_lock=threading.RLock(),closed=False)
        stack.callback(setattr,journal,'closed',True)
        files = InstallationFiles(journal=journal,readonly=True)

        def check():
            if journal.closed:raise Conflict('original readonly catalog capability closed')
            physical()
            try:
                row = db.execute('SELECT identity FROM journal_identity WHERE singleton=1').fetchone()
                if row is None or row['identity'] != binding['identity']:
                    raise Conflict('original logical template catalog differs')
                if files.observe(store_item,store_operation) != store_proof:
                    raise Conflict('original template store birth differs')
            except sqlite3.Error as error:
                raise Conflict('original readonly catalog connection unavailable') from error
            physical()

        check()
        def forbidden(*args,**kwargs):raise Conflict('readonly catalog cannot reopen an import window')
        window = ProvisioningWindow(import_window,forbidden)
        store_parent = {key:store_proof['identity'][key] for key in ('device','inode','uid','gid','mode')}
        catalog = ReadonlyTemplateCatalog(journal,root=store_item['spec']['path'],parent_identity=store_parent,
                                         window=window,preflight=forbidden,readonly=True)
        catalog.check = check
        try:
            yield catalog
        except BaseException as original:
            try:check()
            except Exception as error:original.add_note('catalog final observation also failed: '+str(error))
            raise
        else:check()


def store_reference(catalog):
    """Describe an already qualified original store capability, never acquire it."""
    if (not isinstance(catalog, ReadonlyTemplateCatalog) or not catalog.readonly
            or getattr(catalog.journal, 'closed', False)):
        raise Conflict('live original readonly template store required')
    catalog.check()
    return dict(root=catalog.root, parent=deepcopy(catalog.parent),
                journal_identity=catalog.journal.identity, window_sha256=catalog.window.sha256)


@contextmanager
def open_bundle_catalog(binding, *, store, original_store, publication, import_window,
                        verify, expected_binding=None):
    """Read a later import journal while retaining the original store lease.

    The store birth stays in its original journal. The later journal owns only
    its bundle's directory/file births. Both capabilities must remain live;
    neither journal is opened writable, initialized, or copied into the other.
    """
    binding, original_store, publication, import_window = deepcopy(
        (binding, original_store, publication, import_window))
    if (not isinstance(binding, dict)
            or set(binding) != {'directory', 'identity', 'directory_identity', 'database_identity', 'lock_identity'}
            or not callable(verify) or store_reference(store) != original_store
            or publication.get('directory') != str(Path(original_store['root']) / publication.get('template_sha256', ''))):
        raise Conflict('original bundle journal, publication and store dependency required')
    original_check, original_journal = store.check, store.journal
    def forbidden(*args, **kwargs):
        raise Conflict('readonly bundle catalog cannot reopen an import window')

    window = ProvisioningWindow(import_window, forbidden)
    resource_sha256 = fingerprint(dict(store=original_store, publication=publication))

    def check_inputs():
        verify()
        if (store.check is not original_check or store.journal is not original_journal
                or store_reference(store) != original_store):
            raise Conflict('original template store dependency changed or closed')
        directory = Path(binding['directory'])
        wanted = {'': binding['directory_identity'], 'journal.sqlite3': binding['database_identity'],
                  'workload.lock': binding['lock_identity']}
        for name, expected in wanted.items():
            path = directory / name if name else directory
            if identity(os.stat(path, follow_symlinks=False)) != expected:
                raise Conflict('original bundle journal physical binding differs')

    def driver(journal, kind=TemplateBundleInstall):
        return kind(journal, root=original_store['root'], parent_identity=original_store['parent'],
                    window=window, preflight=forbidden, readonly=True)

    def validate(journal):
        check_inputs()
        observed = driver(journal).observe(publication['operation_id'])
        if observed != publication:
            raise Conflict('original later bundle publication differs')
        check_inputs()
        return resource_sha256

    view = None
    try:
        with readonly_resource_journal(binding['directory'], journal_identity=binding['identity'],
                resource_sha256=resource_sha256, verify=check_inputs, validate=validate,
                expected_binding=expected_binding) as lease:
            view = lease.journal
            view.closed = False
            catalog = driver(view, ReadonlyTemplateCatalog)
            catalog.check = lease.check
            catalog.binding = deepcopy(lease.receipt)
            yield catalog
    finally:
        if view is not None:
            view.closed = True
