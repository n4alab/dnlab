"""Real inert client processes qualify permit/progress persistence without packets."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest
from dnlab_multinode.services.management_probe_exec import CLIENT


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


@pytest.mark.parametrize('mode',['success','failure','killed-before-permit'])
def test_inert_client_waits_for_permit_and_persists_progress_before_exit(tmp_path,mode):
    output=tmp_path/'events';output.write_bytes(b'');output.chmod(0o600);info=output.stat()
    source="def run(profile,progress=None):\n progress('ipv4.offer',{'offer':'inert'})\n"
    source+=" raise RuntimeError('after qualified offer')\n" if mode=='failure' else " return {'result':'inert'}\n"
    nonce='1'*32;fingerprint='a'*64
    text=CLIENT.replace('__SOURCE__',repr(source)).replace('__PROFILE__','{}').replace('__NONCE__',repr(nonce)).replace('__REQUEST__',repr(fingerprint))
    text=text.replace("'/run/dnlab-probe.jsonl'",repr(str(output)))
    program=tmp_path/'client.py';program.write_text(text);program.chmod(0o600)
    child=subprocess.Popen([sys.executable,'-I',str(program),nonce,str(info.st_dev),str(info.st_ino)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while not output.stat().st_size:
            if child.poll() is not None or time.monotonic()>=deadline:pytest.fail('client birth not observed')
            time.sleep(.01)
        birth=records(output);assert len(birth)==1 and birth[0]['kind']=='birth'
        assert birth[0]['value']['pid']==child.pid and child.poll() is None
        time.sleep(.1);assert records(output)==birth
        if mode=='killed-before-permit':
            child.kill();child.wait(timeout=5)
            assert records(output)==birth and child.returncode!=0
            return
        permit={'nonce':nonce,'request':fingerprint,'kind':'permit','value':birth[0]['value']}
        with output.open('a') as stream:stream.write(json.dumps(permit)+'\n');stream.flush();os.fsync(stream.fileno())
        stdout,stderr=child.communicate(timeout=5);assert stdout==b'' and stderr==b'',stderr
        rows=records(output)
        assert [r['kind'] for r in rows]==['birth','permit','progress','failed' if mode=='failure' else 'completed']
        assert rows[2]['value']=={'stage':'ipv4.offer','result':{'offer':'inert'}}
        assert child.returncode==(1 if mode=='failure' else 0)
        if mode=='failure':assert rows[-1]['value']=={'type':'RuntimeError','message':'after qualified offer'}
    finally:
        if child.poll() is None:child.kill()
        child.wait(timeout=5)
        for stream in (child.stdout,child.stderr):stream.close()
