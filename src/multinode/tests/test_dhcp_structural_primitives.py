"""Pre-mutation qualification for the future offline structural operation."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_host_identity import proof


@pytest.mark.parametrize('environment',[
    '', 'DNLAB_DHCP_OPERATION_NONCE='+'b'*32,
    'DNLAB_DHCP_OPERATION_NONCE='+'a'*32+'\0DNLAB_DHCP_OPERATION_NONCE='+'a'*32,
])
def test_missing_foreign_or_duplicate_nonce_does_not_qualify_a_new_process(environment):
    with pytest.raises(module.JumphostError,match='nonce differs'):
        module.dhcp_validate_birth_nonce(environment,'a'*32)


def test_exact_nonce_matches_without_revealing_other_environment_values():
    value='SECRET=do-not-record\0DNLAB_DHCP_OPERATION_NONCE='+'a'*32+'\0PATH=/bin\0'
    assert module.dhcp_validate_birth_nonce(value,'a'*32)=='a'*32
    with pytest.raises(module.JumphostError) as error:
        module.dhcp_validate_birth_nonce(value,'b'*32)
    assert 'SECRET' not in str(error.value) and 'do-not-record' not in str(error.value)


@pytest.mark.parametrize('nonce',['',None,'a'*31,'x'*32])
def test_malformed_intent_nonce_rejected(nonce):
    with pytest.raises(module.JumphostError,match='nonce invalid'):
        module.dhcp_validate_birth_nonce('DNLAB_DHCP_OPERATION_NONCE='+str(nonce),nonce)


def test_syntax_check_uses_original_container_and_stdin_without_an_asset_write():
    worker=SimpleNamespace(run=Mock())
    service=module.DHCPHostService(worker,{},123)
    service.container={'Id':'c'*64};service.recheck_container=Mock()
    content='interface=eth1\nport=0\n'
    assert service.syntax(content)=={'syntax_verified':True}
    worker.run.assert_called_once_with(['docker','exec','-i','c'*64,'dnsmasq','--test','--conf-file=-'],input=content)
    assert service.recheck_container.call_count==2


@pytest.mark.parametrize('when',['container','syntax'])
def test_syntax_or_container_failure_prevents_success(when):
    worker=SimpleNamespace(run=Mock())
    service=module.DHCPHostService(worker,{},123)
    service.container={'Id':'c'*64};service.recheck_container=Mock()
    failure=module.JumphostError('rejected')
    if when=='container':service.recheck_container.side_effect=failure
    else:worker.run.side_effect=failure
    with pytest.raises(module.JumphostError):service.syntax('port=0\n')
    if when=='container':worker.run.assert_not_called()


@pytest.mark.parametrize('outcome',['exit','already-exited','timeout','replacement','bad-fd'])
def test_stop_uses_original_pidfd_and_never_forces_or_restarts(monkeypatch,outcome):
    worker=SimpleNamespace(infrastructure=Mock(),verify_attachment=Mock(),verify_extensions=Mock())
    record={};service=module.DHCPHostService(worker,record,123)
    original=proof();service.observe=Mock(return_value=original);service.recheck_container=Mock()
    if outcome=='replacement':service.observe.side_effect=[original,module.JumphostError('generation changed')]
    opened=[];closed=[];signals=[]
    monkeypatch.setattr(module.os,'pidfd_open',lambda pid:opened.append(pid) or 9876)
    monkeypatch.setattr(module.os,'close',lambda fd:closed.append(fd))
    def signal(fd,value):
        signals.append((fd,value))
        if outcome=='already-exited':raise ProcessLookupError()
    monkeypatch.setattr(module.signal,'pidfd_send_signal',signal)
    events=[] if outcome=='timeout' else [(9876,module.select.POLLNVAL if outcome=='bad-fd' else module.select.POLLIN)]
    poll=SimpleNamespace(register=Mock(),poll=Mock(return_value=events))
    monkeypatch.setattr(module.select,'poll',lambda:poll)
    try:
        if outcome in ('timeout','replacement','bad-fd'):
            with pytest.raises(module.JumphostError):service.stop(original)
        else:assert service.stop(original)=={'service':original,'exit_verified':True}
        assert opened==[original['host_pid']]
        worker.infrastructure.assert_called_once_with(record)
        worker.verify_attachment.assert_called_once_with(record,123)
        worker.verify_extensions.assert_called_once_with(record)
        if outcome=='replacement':assert signals==[]
        else:
            assert signals==[(9876,module.signal.SIGTERM)]
            poll.poll.assert_called_once_with(5000)
    finally:service.stack.close()
    assert closed==[9876]


def test_shutdown_without_original_proof_is_rejected_before_preflight():
    worker=SimpleNamespace(infrastructure=Mock())
    service=module.DHCPHostService(worker,{},123)
    with pytest.raises(module.JumphostError,match='original DHCP process proof'):
        service.stop(None)
    worker.infrastructure.assert_not_called()
