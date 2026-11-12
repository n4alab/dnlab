"""Inherited-FD formatter entry; an original tracked parent must release it."""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.vm_overlay_worker import serve


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-fd', required=True, type=int)
    parser.add_argument('--overlay-fd', required=True, type=int)
    parser.add_argument('--close-on-exec-fd', action='append', default=[], type=int)
    args = parser.parse_args()
    descriptors = [args.binary_fd, args.overlay_fd, *args.close_on_exec_fd]
    if any(fd < 3 for fd in descriptors) or len(set(descriptors)) != len(descriptors):
        parser.error('distinct inherited formatter descriptors required')

    def execute(fd, argv, environment):
        for other in args.close_on_exec_fd:os.set_inheritable(other, False)
        os.set_inheritable(fd, False)
        os.set_inheritable(args.overlay_fd, True)
        os.execve(fd, argv, environment)

    serve(sys.stdin, sys.stdout, args.binary_fd, args.overlay_fd, execute=execute)


if __name__ == '__main__':main()
