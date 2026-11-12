"""Read bounded storage identity fields, not qcow2 allocation-table consistency.

Follows QEMU's interop/qcow2 specification. No backing file is opened here.
The caller owns the FD, verifies the base separately and qualifies any writer.
"""
import os
import struct

from .vm_template import require


def inspect_header(fd, *, allow_dirty=False):
    initial = os.pread(fd, 104, 0)
    require(len(initial) >= 72 and initial[:4] == b'QFI\xfb', 'complete qcow2 header required')
    version = struct.unpack_from('>I', initial, 4)[0]
    backing, length, bits = struct.unpack_from('>QII', initial, 8)
    size, crypt = struct.unpack_from('>QI', initial, 24)
    snapshots = struct.unpack_from('>I', initial, 60)[0]
    require(version in (2, 3) and 9 <= bits <= 21 and 0 < size < 2**63 and crypt == 0
            and snapshots == 0, 'qualified unencrypted qcow2 layout without snapshots required')
    header_length = 72
    dirty = False
    if version == 3:
        require(len(initial) == 104, 'complete version-3 qcow2 header required')
        incompatible, compatible, autoclear = struct.unpack_from('>QQQ', initial, 72)
        header_length = struct.unpack_from('>I', initial, 100)[0]
        require(incompatible & ~1 == 0 and compatible == 0 and autoclear == 0
                and header_length in (104, 112), 'unsupported qcow2 features or header version')
        dirty = bool(incompatible & 1)
    require(allow_dirty or not dirty, 'dirty qcow2 requires an original qualified writer')
    cluster = os.pread(fd, 1 << bits, 0)
    require(len(cluster) == 1 << bits, 'complete first qcow2 cluster required')
    before, after = bytearray(initial), bytearray(cluster[:len(initial)])
    if version == 3 and allow_dirty:
        dirty = dirty or bool(after[79] & 1)
        before[79] &= ~1; after[79] &= ~1
    require(before == after, 'qcow2 header changed during observation')
    if header_length > 104:
        require(cluster[104:header_length] == b'\0' * (header_length - 104), 'unsupported qcow2 compression/header fields')
    require((backing == 0 and length == 0) or (0 < length <= 4096
            and header_length <= backing and backing + length <= len(cluster)), 'bounded qcow2 backing filename required')
    limit = backing or len(cluster)
    offset = header_length
    extensions = {}
    while offset + 8 <= limit:
        kind, count = struct.unpack_from('>II', cluster, offset)
        offset += 8
        if kind == 0:
            require(count == 0, 'malformed qcow2 extension terminator')
            break
        end = offset + count
        require(kind not in extensions and end <= limit and kind not in (0x44415441, 0x0537BE77, 0x23852875),
                'duplicate, truncated or unsupported qcow2 storage extension')
        extensions[kind] = cluster[offset:end]
        offset = (end + 7) & ~7
    else:
        require(False, 'qcow2 extension terminator missing')
    name = os.fsdecode(cluster[backing:backing + length]) if backing else None
    require(name is None or '\0' not in name, 'qcow2 backing filename contains NUL')
    raw_format = extensions.get(0xE2792ACA)
    require(raw_format is None or raw_format in (b'raw', b'qcow2'), 'unsupported qcow2 backing format')
    return dict(format='qcow2', virtual_size=size, backing_path=name,
                backing_format=raw_format.decode('ascii') if raw_format else None, dirty=dirty)
