"""Storage-identity header fields only; synthetic images are not bootable."""
import os
import struct

import pytest

from dnlab_runtime.qcow2_header import inspect_header
from dnlab_runtime.vm_template import TemplateError


def header(backing='/templates/base.raw', format='raw', size=4096):
    data = bytearray(4096)
    name = os.fsencode(backing) if backing else b''
    struct.pack_into('>IIQIIQI', data, 0, 0x514649FB, 3, 256 if name else 0, len(name), 12, size, 0)
    struct.pack_into('>QQQII', data, 72, 0, 0, 0, 4, 104)
    if format is not None:
        raw = format.encode();struct.pack_into('>II', data, 104, 0xE2792ACA, len(raw))
        data[112:112+len(raw)] = raw
    if name:data[256:256+len(name)] = name
    return bytes(data)


def test_pread_retains_offset_and_reads_explicit_backing(tmp_path):
    file = tmp_path/'overlay';file.write_bytes(header())
    fd = os.open(file, os.O_RDONLY)
    try:
        os.lseek(fd, 7, os.SEEK_SET)
        assert inspect_header(fd) == dict(format='qcow2',virtual_size=4096,backing_path='/templates/base.raw',backing_format='raw',dirty=False)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 7
    finally:os.close(fd)


@pytest.mark.parametrize('fault', ['corrupt', 'external', 'encrypted', 'snapshot', 'path-bound', 'extension-duplicate', 'truncated'])
def test_incompatible_or_malformed_headers_refuse_identity(tmp_path, fault):
    data = bytearray(header())
    if fault == 'corrupt':struct.pack_into('>Q', data, 72, 2)
    elif fault == 'external':struct.pack_into('>Q', data, 72, 4)
    elif fault == 'encrypted':struct.pack_into('>I', data, 32, 2)
    elif fault == 'snapshot':struct.pack_into('>I', data, 60, 1)
    elif fault == 'path-bound':struct.pack_into('>Q', data, 8, 4090)
    elif fault == 'extension-duplicate':struct.pack_into('>II', data, 120, 0xE2792ACA, 3)
    else:data = data[:90]
    file = tmp_path/'invalid';file.write_bytes(data)
    fd = os.open(file, os.O_RDONLY)
    try:
        with pytest.raises(TemplateError):inspect_header(fd)
    finally:os.close(fd)


def test_dirty_bit_requires_qualified_writer_policy(tmp_path):
    data = bytearray(header());struct.pack_into('>Q', data, 72, 1)
    file = tmp_path/'active';file.write_bytes(data)
    fd = os.open(file, os.O_RDONLY)
    try:
        with pytest.raises(TemplateError,match='qualified writer'):inspect_header(fd)
        assert inspect_header(fd,allow_dirty=True)['dirty'] is True
    finally:os.close(fd)


def test_dirty_transition_during_read_is_not_reported_clean(tmp_path,monkeypatch):
    file=tmp_path/'transition';file.write_bytes(header())
    original=os.pread
    def changed(fd,size,offset):
        data=bytearray(original(fd,size,offset))
        if size>104:data[79]|=1
        return bytes(data)
    monkeypatch.setattr(os,'pread',changed)
    fd=os.open(file,os.O_RDONLY)
    try:assert inspect_header(fd,allow_dirty=True)['dirty'] is True
    finally:os.close(fd)
