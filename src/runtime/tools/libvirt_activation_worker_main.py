"""Private inherited-FD activation entry; no launch from ordinary imports."""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.libvirt_activation_worker import serve


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-fd',required=True,type=int)
    parser.add_argument('--close-on-exec-fd',action='append',default=[],type=int)
    args=parser.parse_args()
    if args.binary_fd<3 or any(fd<3 or fd==args.binary_fd for fd in args.close_on_exec_fd):
        parser.error('private inherited descriptors required')
    def execute(fd,argv,environment):
        for other in args.close_on_exec_fd:os.set_inheritable(other,False)
        os.set_inheritable(fd,False)
        os.execve(fd,argv,environment)
    serve(sys.stdin,sys.stdout,args.binary_fd,execute=execute)


if __name__=='__main__':main()
