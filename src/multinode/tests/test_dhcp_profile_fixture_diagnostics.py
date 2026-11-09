"""Fixture observation preserves original rejection and never accepts a digest."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/tools'))
from dhcp_profile_diagnostics import observe_validator,compare_reference
from dnlab_multinode.services import jumphost_host as host
from tests.test_dhcp_log_identity import log_proof,MAIN


def inputs():
    service,value=log_proof()
    service.update(pid=7,command=['dnsmasq','--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf'],
        uids=[65534]*4,gids=[30]*4,pid_file={},pid_namespace={},net_namespace={},mount_namespace={},binary={},mapped_binary={})
    main=MAIN+'# private-marker-do-not-save\n'
    value['configuration_sha256']=hashlib.sha256(main.encode()).hexdigest()
    return service,value,main


def test_observer_records_before_unchanged_validator_rejects_and_restores_hook(tmp_path):
    service,value,main=inputs();service['container']['image']='sha256:'+'f'*64
    original=host.dhcp_validate_log;profiles=deepcopy(host.DHCP_LOG_PROFILES)
    path=tmp_path/'proof.json';seen=[]
    previous=sys.getprofile()
    def prior(frame,event,arg):pass
    try:
        sys.setprofile(prior)
        def callback():
            try:original(value,service,main)
            except host.JumphostError:
                seen.append(json.loads(path.read_text())['status']);raise
        result=observe_validator(callback,path)
        assert sys.getprofile() is prior
    finally:sys.setprofile(previous)
    assert result['status']=='diagnosed' and result['original_validator_returned'] is False
    assert result['original_error']['message']=='DHCP log image/configuration profile not qualified'
    assert seen==['captured-before-original-validator']
    assert host.dhcp_validate_log is original and host.DHCP_LOG_PROFILES==profiles
    assert result['observations'][0]['image_profile_present'] is False
    assert all(next(iter(result['observations'][0]['reference_comparisons'].values())).values())
    assert 'private-marker-do-not-save' not in path.read_text()
    assert path.stat().st_mode & 0o777==0o600


def test_no_snapshot_claim_when_observation_fails_before_validator(tmp_path):
    def callback():raise host.JumphostError('earlier identity check failed')
    result=observe_validator(callback,tmp_path/'proof.json')
    assert result['status']=='incomplete' and result['observations']==[]


def test_unexpected_guard_success_is_not_reported_as_diagnosed(tmp_path):
    service,value,main=inputs()
    result=observe_validator(lambda:host.dhcp_validate_log(value,service,main),tmp_path/'proof.json')
    assert result['original_validator_returned'] is True and result['status']=='incomplete'


@pytest.mark.parametrize('change',['binary','gid','mode','nlink','uid','directory','writer','facility','hash'])
def test_reference_comparison_exposes_differences(change):
    service,value,main=inputs();profile=next(iter(host.DHCP_LOG_PROFILES.values()))
    if change=='binary':service['binary_sha256']='wrong'
    if change=='gid':value['file']['gid']=30
    if change=='mode':value['file']['mode']=0o666
    if change=='nlink':value['file']['nlink']=2
    if change=='uid':value['file']['uid']=0
    if change=='directory':value['directories'][1]['mode']=0o777
    if change=='writer':value['writer']['host_pid']+=1
    if change=='facility':main+='log-facility=/tmp/other\n'
    if change=='hash':value['configuration_sha256']='wrong'
    assert not all(compare_reference(value,service,main,profile).values())
