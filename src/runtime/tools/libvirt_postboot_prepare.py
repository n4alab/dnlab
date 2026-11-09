"""Deliver a metadata-only prepare into an already qualified private output FD.

The native caller must qualify/open the original journal and output directory
before constructing the session. This module does not open a host journal,
discover a replacement context, apply directory recovery or start services.
An explicit resume reuses the same intent and checks the original reference.
"""
from copy import deepcopy
import json
import os
import stat

from dnlab_runtime.manifest import Conflict,canonical,fingerprint


class PrepareDelivery:
    def __init__(self,session,output_fd):
        self.session=session
        self.fd=os.dup(output_fd)
        try:
            info=os.fstat(self.fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
                raise Conflict('qualified private prepare output required')
        except BaseException:
            os.close(self.fd);self.fd=None
            raise
        self.intent=dict(kind='postboot-prepare-delivery-v1',journal_identity=session.journal_identity,
            source_sha256=fingerprint(session.original),context=deepcopy(session.context),
            qualification_id=session.qualification_id,recovery_id=session.recovery_id,
            run_parent=deepcopy(session.parent),window_sha256=session.window_sha256)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None

    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def _read(self,name):
        if self.fd is None:raise Conflict('prepare output closed')
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd)
        except FileNotFoundError:return None
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>4*1024*1024):
                raise Conflict('original prepare artifact metadata differs: '+name)
            with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(4*1024*1024+1)
            try:value=json.loads(raw)
            except (ValueError,UnicodeError) as error:
                raise Conflict('prepare artifact incomplete; preserve pending: '+name) from error
            after=os.fstat(fd);visible=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if (any(getattr(before,key)!=getattr(after,key) or getattr(before,key)!=getattr(visible,key) for key in fields)
                    or len(raw)!=before.st_size or raw!= (canonical(value)+'\n').encode()):
                raise Conflict('original prepare artifact changed: '+name)
            # An earlier write may have completed while its fsync/response was lost.
            # Confirm the original file and directory, never rewrite that artifact.
            os.fsync(fd);os.fsync(self.fd)
            return value
        finally:os.close(fd)

    def _write(self,name,value):
        if self.fd is None:raise Conflict('prepare output closed')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            with os.fdopen(os.dup(fd),'w') as stream:
                stream.write(canonical(value)+'\n');stream.flush()
            os.fsync(fd);os.fsync(self.fd)
        finally:os.close(fd)

    def prepare(self,*,resume=False):
        if type(resume) is not bool:raise Conflict('explicit prepare resume mode required')
        with self.session.journal.execution_lock:
            self.session._source()
            if resume:
                if self._read('intent.json')!=self.intent:raise Conflict('original prepare delivery intent differs')
            else:
                if self._read('prepared-reference.json') is not None:
                    raise Conflict('prepare output already contains a reference')
                self._write('intent.json',self.intent)
            reference=self._read('prepared-reference.json')
            if reference is None:
                reference=self.session.prepare()
                self._write('prepared-reference.json',reference)
            else:
                current=self.session._binding(reference)
                if current['phase']!='prepared':raise Conflict('directory recovery started; prepare delivery cannot resume')
                self.session.qualification.observe_persistent(self.session.qualification_id)
            self.session._binding(reference)
            self.session._source()
            return deepcopy(reference)
