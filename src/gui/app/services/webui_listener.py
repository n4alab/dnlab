"""Read-only Linux proof of a listener held by one original child process."""
from contextlib import ExitStack
import ipaddress
import os
import re
import select


class ListenerError(RuntimeError):
    pass


class Listener:
    def __init__(self, proc):
        self.proc = proc
        self.stack = ExitStack()

    def __enter__(self):
        try:
            self.pid = self.proc.pid
            if type(self.pid) is not int or self.pid <= 0:
                raise ListenerError('invalid original SSH PID')
            self.pidfd = os.pidfd_open(self.pid)
            self.stack.callback(os.close, self.pidfd)
            self.directory = os.open('/proc/' + str(self.pid), os.O_RDONLY | os.O_DIRECTORY)
            self.stack.callback(os.close, self.directory)
            self.namespace = os.open('ns/net', os.O_RDONLY, dir_fd=self.directory)
            self.stack.callback(os.close, self.namespace)
            self.identity = self.observe()
            return self
        except Exception:
            self.stack.close()
            raise

    def __exit__(self, *args):
        self.stack.close()

    @staticmethod
    def ns_identity(path):
        value = os.stat(path)
        return value.st_dev, value.st_ino

    def read(self, name):
        fd = os.open(name, os.O_RDONLY, dir_fd=self.directory)
        with os.fdopen(fd) as stream:
            return stream.read()

    def observe(self):
        if self.proc.poll() is not None or select.select([self.pidfd], [], [], 0)[0]:
            raise ListenerError('original SSH process exited')
        fields = self.read('stat').rsplit(')', 1)
        if len(fields) != 2 or int(fields[0].split(' ', 1)[0]) != self.pid:
            raise ListenerError('original SSH process stat differs')
        tail = fields[1].split()
        if len(tail) < 20 or tail[0] in ('Z', 'X') or not tail[19].isdecimal():
            raise ListenerError('original SSH process stat incomplete or exited')
        info = os.fstat(self.directory)
        if (info.st_dev, info.st_ino) != self.ns_identity('/proc/' + str(self.pid)):
            raise ListenerError('original SSH process directory changed')
        net = os.fstat(self.namespace)
        identity = {'pid': self.pid, 'start': tail[19], 'directory': (info.st_dev, info.st_ino),
                    'namespace': (net.st_dev, net.st_ino)}
        if identity['namespace'] != self.ns_identity('/proc/' + str(self.pid) + '/ns/net'):
            raise ListenerError('original SSH namespace changed')
        if identity['namespace'] != self.ns_identity('/proc/self/ns/net'):
            raise ListenerError('local network namespace changed')
        return identity

    def recheck(self):
        if self.observe() != self.identity:
            raise ListenerError('original SSH process generation changed')

    def inodes(self):
        fd = os.open('fd', os.O_RDONLY | os.O_DIRECTORY, dir_fd=self.directory)
        try:
            result = set()
            for name in os.listdir(fd):
                if not name.isdecimal():
                    continue
                try:
                    link = os.readlink(name, dir_fd=fd)
                except FileNotFoundError:
                    continue
                match = re.fullmatch(r'socket:\[(\d+)\]', link)
                if match:
                    result.add(int(match[1]))
            return result
        finally:
            os.close(fd)

    @staticmethod
    def encoded(address):
        raw = ipaddress.ip_address(address).packed
        return ''.join(raw[i:i+4][::-1].hex() for i in range(0, len(raw), 4))

    def candidates(self, host, port):
        wanted = self.encoded(host)
        mapped = self.encoded('::ffff:' + host)
        result = []
        for table, addresses, width in (('tcp', {wanted, '0'*8}, 8), ('tcp6', {mapped, '0'*32}, 32)):
            lines = self.read('net/' + table).splitlines()
            header = lines[0].split() if lines else []
            if (len(header) < 4 or header[:2] != ['sl', 'local_address']
                    or header[2] not in ('rem_address', 'remote_address') or header[3] != 'st'):
                raise ListenerError('listener table header differs')
            for line in lines[1:]:
                row = line.split()
                if len(row) < 10:
                    raise ListenerError('listener table incomplete')
                if row[3] != '0A':
                    continue
                if not re.fullmatch(r'[0-9A-Fa-f]{' + str(width) + r'}:[0-9A-Fa-f]{4}', row[1]):
                    raise ListenerError('listener address malformed')
                address, number = row[1].lower().split(':')
                if int(number, 16) != port or address not in addresses:
                    continue
                if row[2] != '0'*width + ':0000' or not row[9].isdecimal() or int(row[9]) <= 0:
                    raise ListenerError('listener identity incomplete')
                result.append({'table': table, 'address': address, 'port': port, 'inode': int(row[9])})
        return result

    def proof(self, host, port):
        self.recheck()
        before = self.inodes()
        rows = self.candidates(host, port)
        after = self.inodes()
        latest = self.candidates(host, port)
        if latest != rows:
            self.recheck()
            # Startup may create the owned socket between these two reads.
            # A later iteration must still establish a complete stable proof.
            if (not rows and len(latest) == 1 and ipaddress.ip_address(host).is_loopback
                    and latest[0]['table'] == 'tcp' and latest[0]['address'] == self.encoded(host)
                    and latest[0]['port'] == port and latest[0]['inode'] in after):
                return None
            raise ListenerError('listener changed during observation')
        self.recheck()
        if not rows:
            return None
        if (len(rows) != 1 or rows[0]['table'] != 'tcp' or rows[0]['address'] != self.encoded(host)
                or rows[0]['inode'] not in before & after):
            raise ListenerError('local listener is conflicting or not owned by original SSH process')
        return dict(rows[0], process=self.identity)
