"""Real local processes for the frozen program; no Docker or lab resources."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
from jumphost_cli_program import build


def fixture(tmp_path, code, *, timeout=2):
    cli=tmp_path/'vd';cli.write_text('#!'+sys.executable+'\n'+code);cli.chmod(0o755)
    output=tmp_path/'output';output.touch(mode=0o600);info=output.stat()
    profile={'nonce':'a'*32,'output':str(output),'identity':[info.st_dev,info.st_ino,info.st_uid,info.st_gid],
             'cli':str(cli),'action':'connect','node':'R1','command_hex':b'first-command\n'.hex(),
             'marker_hex':b'qualified-response'.hex(),'timeout':timeout}
    return profile,output


def rows(output):
    return [json.loads(line) for line in output.read_text().splitlines()]


def live(birth):
    try:
        fields=(Path('/proc')/str(birth['pid'])/'stat').read_text().rsplit(')',1)[1].split()
        return fields[19]==birth['start'] and fields[0]!='Z'
    except FileNotFoundError:
        return False


def test_program_records_birth_output_order_and_verified_child_exit(tmp_path):
    profile,output=fixture(tmp_path,"import sys;sys.stdin.buffer.readline();print('qualified-response',flush=True);sys.stdin.buffer.read()\n")
    result=subprocess.run([sys.executable,'-I','-c',build(profile),profile['nonce']],capture_output=True,timeout=5)
    assert result.returncode==0, result.stderr
    events=rows(output)
    assert [r['kind'] for r in events[:2]]==['wrapper_birth','client_birth']
    assert all(r['nonce']==profile['nonce'] for r in events)
    terminal=events[-1]
    assert terminal['kind']=='completed' and terminal['value']['exit_verified']
    assert bytes.fromhex(terminal['value']['output_hex'])==b'qualified-response\n'
    assert terminal['value']['marker_seen_before_input_close']
    assert not live(events[1]['value'])


def test_timeout_reaps_original_child_before_failure_receipt(tmp_path):
    profile,output=fixture(tmp_path,'import time;time.sleep(60)\n',timeout=.1)
    result=subprocess.run([sys.executable,'-I','-c',build(profile),profile['nonce']],capture_output=True,timeout=5)
    events=rows(output)
    assert result.returncode==1 and events[-1]['kind']=='failed'
    assert events[-1]['value']['client_exit_verified'] and not live(events[1]['value'])


def test_abrupt_wrapper_death_cannot_leave_client_running(tmp_path):
    profile,output=fixture(tmp_path,'import time;time.sleep(60)\n',timeout=10)
    wrapper=subprocess.Popen([sys.executable,'-I','-c',build(profile),profile['nonce']],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    birth=None
    try:
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            clients=[r['value'] for r in rows(output) if r['kind']=='client_birth']
            if clients:
                birth=clients[0];break
            time.sleep(.02)
        assert birth is not None and live(birth)
        wrapper.kill();wrapper.wait(timeout=3)
        deadline=time.monotonic()+3
        while live(birth) and time.monotonic()<deadline:time.sleep(.02)
        assert not live(birth)
        assert not any(r['kind']=='completed' for r in rows(output))
    finally:
        if wrapper.poll() is None:wrapper.kill()
        wrapper.wait(timeout=3);wrapper.stdout.close();wrapper.stderr.close()


@pytest.mark.parametrize('replacement',['inode','mode'])
def test_output_asset_conflict_is_refused_before_client_spawn(tmp_path,replacement):
    profile,output=fixture(tmp_path,"print('qualified-response')\n")
    if replacement=='inode':profile['identity'][1]+=1
    else:output.chmod(0o644)
    result=subprocess.run([sys.executable,'-I','-c',build(profile),profile['nonce']],capture_output=True,timeout=5)
    assert result.returncode!=0 and output.read_bytes()==b''


def test_invalid_profile_does_not_produce_executable_program(tmp_path):
    profile,output=fixture(tmp_path,'pass\n')
    profile['command_hex']=profile['marker_hex']
    with pytest.raises(ValueError,match='distinct'):build(profile)
