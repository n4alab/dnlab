"""Bounded readonly readers for the declared local cleanup census."""
import hashlib
import os
from pathlib import Path
import stat

from cleanup_census import candidate
from cleanup_container_observer import metadata
from cleanup_execution import require, absolute


class CensusArgumentError(ValueError):
    """Classification failure with bounded metadata, never raw arguments."""

    def __init__(self, pid, raw, error):
        fields = raw[:-1].split(b'\0') if raw.endswith(b'\0') else raw.split(b'\0')
        self.evidence = {
            'pid': pid, 'cmdline_sha256': hashlib.sha256(raw).hexdigest(),
            'byte_count': len(raw), 'argument_count': len(fields),
            'empty_indices': [index for index, field in enumerate(fields) if not field],
            'terminated': raw.endswith(b'\0'), 'cause_type': type(error).__name__,
        }
        super().__init__('process argv cannot be classified; see private argument metadata')


def read_regular(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode), 'regular census source required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            require(size <= limit, 'census source exceeds read bound')
        require(metadata(os.fstat(fd)) == metadata(first)
                and metadata(os.lstat(path)) == metadata(first), 'census source changed during read')
        return b''.join(chunks), metadata(first)
    finally:
        os.close(fd)


def process_inventory(proc='/proc'):
    """Scan recognizable entrypoints; unrelated commands are not retained."""
    root = Path(proc)
    entries = sorted((path for path in root.iterdir() if path.name.isdecimal()), key=lambda p: int(p.name))
    require(len(entries) <= 32768, 'process inventory exceeds bound')
    rows = []
    for path in entries:
        try:
            first, _ = read_regular(path / 'stat', 16384)
            raw, _ = read_regular(path / 'cmdline', 65536)
            if not raw:
                continue
            try:
                require(raw.endswith(b'\0'), 'incomplete process command observation')
                argv = [word.decode() for word in raw[:-1].split(b'\0')]
                recognized = candidate(argv)
            except (ValueError, UnicodeError) as error:
                raise CensusArgumentError(int(path.name), raw, error) from None
            if not recognized:
                continue
            def ticks(value):
                head, tail = value.decode().rsplit(')', 1)
                require(int(head.split('(', 1)[0]) == int(path.name), 'process PID differs')
                value = tail.split()[19]
                require(value.isdecimal() and int(value) > 0, 'process starttime unavailable')
                return value
            after, _ = read_regular(path / 'stat', 16384)
            again, _ = read_regular(path / 'cmdline', 65536)
            require(ticks(first) == ticks(after) and raw == again,
                    'candidate process changed during census')
            rows.append({'pid': int(path.name), 'start_ticks': ticks(first), 'argv': argv})
        except FileNotFoundError:
            # Only an observed vanished process can be omitted, never an
            # unreadable field of a still-present process.
            require(not path.exists(), 'process census field missing')
    return rows


def scheduled_sources(paths):
    """Read explicit roots; symlink targets are data and never followed."""
    require(type(paths) is list and paths and all(absolute(path) for path in paths)
            and len(set(paths)) == len(paths), 'explicit distinct scheduled roots required')
    rows, seen = [], set()
    def visit(path, depth=0):
        name = str(path)
        if name in seen:
            return
        require(depth <= 16 and len(rows) < 8192, 'scheduled census exceeds bound')
        seen.add(name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            rows.append({'source_id': name, 'kind': 'absent'})
            return
        before = metadata(info)
        row = {'source_id': name, 'metadata': before}
        if stat.S_ISREG(info.st_mode):
            raw, observed = read_regular(path)
            require(observed == before, 'scheduled source identity changed')
            row.update(kind='file', sha256=hashlib.sha256(raw).hexdigest())
        elif stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            children = sorted(path.iterdir(), key=lambda item: item.name)
            require(len(children) <= 8192, 'scheduled directory exceeds bound')
            row.update(kind='directory', names=[item.name for item in children])
            rows.append(row)
            for child in children:
                visit(child, depth + 1)
            require(metadata(path.lstat()) == before, 'scheduled directory changed during census')
            return
        else:
            raise ValueError('unsupported scheduled source type')
        require(metadata(path.lstat()) == before, 'scheduled source changed during census')
        rows.append(row)
    for path in paths:
        visit(Path(path))
    return {'complete': True, 'candidates': sorted(rows, key=lambda row: row['source_id'])}
