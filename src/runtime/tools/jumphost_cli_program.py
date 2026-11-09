"""Frozen fixture program for an owned detached exec; no image changes."""
import math
from pathlib import Path
import re


PROGRAM = r'''
import ctypes,json,os,signal,stat,subprocess,sys
PROFILE=__PROFILE__
PUMP=__PUMP__
if sys.argv[1:] != [PROFILE['nonce']]:raise RuntimeError('CLI invocation nonce differs')
fd=os.open(PROFILE['output'],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
info=os.fstat(fd)
if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1
    or [info.st_dev,info.st_ino,info.st_uid,info.st_gid]!=PROFILE['identity']
    or info.st_uid!=os.getuid()):raise RuntimeError('CLI output asset differs')
def emit(kind,value):
    raw=(json.dumps({'nonce':PROFILE['nonce'],'kind':kind,'value':value},sort_keys=True)+'\n').encode()
    if os.fstat(fd).st_size+len(raw)>1048576:raise RuntimeError('CLI journal bound exceeded')
    view=memoryview(raw)
    while view:
        count=os.write(fd,view)
        if not count:raise RuntimeError('CLI progress write incomplete')
        view=view[count:]
    os.fsync(fd)
def birth(pid):
    ns=os.stat('/proc/'+str(pid)+'/ns/net')
    return {'pid':pid,'start':open('/proc/'+str(pid)+'/stat').read().rsplit(')',1)[1].split()[19],
            'namespace':[ns.st_dev,ns.st_ino]}
parent=os.getpid()
libc=ctypes.CDLL(None,use_errno=True)
def parent_death():
    # PR_SET_PDEATHSIG=1 from linux/prctl.h. No credential transitions occur
    # after this call; wrapper and CLI both run as the same exec user.
    if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:os._exit(125)
process=None;failure=None;result=None
try:
    emit('wrapper_birth',birth(parent))
    process=subprocess.Popen([PROFILE['cli'],PROFILE['action'],PROFILE['node']],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=parent_death)
    emit('client_birth',birth(process.pid))
    scope={};exec(PUMP,scope)
    def progress(row):
        emit('progress',{'stdout_bytes':len(row['stdout_hex'])//2,'stderr_bytes':len(row['stderr_hex'])//2,
            'marker_seen':row['marker_seen'],'input_closed':row['input_closed'],'exit_code':row['exit_code']})
    result=scope['exchange'](process,bytes.fromhex(PROFILE['command_hex']),bytes.fromhex(PROFILE['marker_hex']),
        timeout=PROFILE['timeout'],observe=progress)
except Exception as error:
    failure={'type':type(error).__name__,'message':str(error)[:500]}
finally:
    # Only the unreaped direct child is signalled. Never discover/kill by name.
    if process is not None:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        process.stdout.close();process.stderr.close()
    if failure is None:
        result['output_hex']=result.pop('output').hex();result['nonce']=PROFILE['nonce']
        emit('completed',result)
    else:
        emit('failed',{'error':failure,'client_exit_verified':process is not None and process.returncode is not None})
    os.close(fd)
if failure is not None:sys.exit(1)
'''


def build(profile):
    required={'nonce','output','identity','cli','action','node','command_hex','marker_hex','timeout'}
    if (not isinstance(profile,dict) or set(profile)!=required
            or not re.fullmatch('[0-9a-f]{32}',str(profile['nonce']))
            or profile['action'] not in ('connect','log')
            or not re.fullmatch('[A-Za-z0-9_.-]{1,128}',str(profile['node']))
            or not all(isinstance(profile[k],str) and Path(profile[k]).is_absolute()
                       and '..' not in Path(profile[k]).parts for k in ('output','cli'))
            or not isinstance(profile['identity'],list) or len(profile['identity'])!=4
            or any(type(v) is not int or v<0 for v in profile['identity'])
            or type(profile['timeout']) not in (int,float) or not math.isfinite(profile['timeout'])
            or not 0<profile['timeout']<=30):
        raise ValueError('qualified bounded CLI program profile required')
    try:
        command,marker=(bytes.fromhex(profile[k]) for k in ('command_hex','marker_hex'))
    except (ValueError,TypeError) as error:
        raise ValueError('CLI command and marker must be hexadecimal bytes') from error
    if not command or len(command)>4096 or not marker or marker in command:
        raise ValueError('distinct response marker required')
    pump=Path(__file__).with_name('console_input_fixture.py').read_text()
    source=PROGRAM.replace('__PROFILE__',repr(profile)).replace('__PUMP__',repr(pump))
    compile(source,'<qualified-cli-program>','exec')
    return source
