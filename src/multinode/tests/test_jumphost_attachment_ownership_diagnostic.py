"""Public jumphost boundary regressions for ownership and no name-based cleanup."""
from unittest.mock import MagicMock
import pytest
from dnlab_multinode.services import jumphost
from dnlab_multinode.services.jumphost_host import names


def test_jumphost_attachment_names_distinguish_full_lab_identity():
    assert names("breakout-alpha") != names("breakout-beta")
    assert names("breakout-alpha", "a") != names("breakout-alpha", "b")


def test_jumphost_attachment_refuses_missing_birth_before_mutation(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(jumphost, "_guard", lambda *a: {"phase": "absent"})
    with pytest.raises(RuntimeError, match="birth record missing"):
        jumphost.attach_jumphost_to_mgmt_bridge(client, container="foreign", lab_name="breakout-alpha",
            bridge="br-management", mgmt_ip="192.0.2.254", mgmt_subnet="192.0.2.0/24")
    client.run.assert_not_called()


def test_jumphost_deploy_qualifies_container_before_first_mutation(topo_factory, monkeypatch):
    client = MagicMock()
    def reject(*a): raise RuntimeError("foreign generation")
    monkeypatch.setattr(jumphost, "_guard", reject)
    with pytest.raises(RuntimeError, match="foreign generation"):
        jumphost.deploy_jumphost(topo_factory(name="breakout-alpha"), client, "172.20.0.254")
    client.run.assert_not_called(); client.run_no_check.assert_not_called()


def test_guard_sends_credentials_only_over_stdin():
    import json
    client=MagicMock();client.run_input.return_value='{"phase":"active"}'
    jumphost._guard(client,'demo','ensure',{'password':'private-password-marker'})
    command,payload=client.run_input.call_args.args
    assert 'private-password-marker' not in command
    assert json.loads(payload)['request']['config']['password']=='private-password-marker'
    client.run.assert_not_called()
