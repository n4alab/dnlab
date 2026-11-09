"""No-host reproductions for shared jumphost external-network admission."""
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.models.topology import JumphostNet
from dnlab_multinode.services.jumphost import ensure_jumphost_network


def test_incompatible_shared_subnet_is_rejected_before_returning_success():
    client = MagicMock()
    client.run_input.side_effect = RuntimeError('external network IPAM differs')
    expected = JumphostNet(network='dnlab-jumphost', bridge='dnlab-jh', ipv4_subnet='172.31.240.0/24', ipv4_gw='172.31.240.1')
    assert expected.ipv4_subnet != '192.0.2.0/24'
    with pytest.raises(RuntimeError):
        ensure_jumphost_network(client, expected)
    client.run.assert_not_called()
    client.run_no_check.assert_not_called()
    client.run_input.assert_called_once()


def test_inspection_denied_cannot_authorize_network_creation():
    client = MagicMock()
    client.run_input.side_effect = RuntimeError('Docker HTTP 403: GET /networks')
    rejection = None
    try:
        ensure_jumphost_network(client, JumphostNet(network='dnlab-jumphost', bridge='dnlab-jh', ipv4_subnet='172.31.240.0/24', ipv4_gw='172.31.240.1'))
    except RuntimeError as error:
        rejection = error
    client.run.assert_not_called()
    client.run_no_check.assert_not_called()
    client.run_input.assert_called_once()
    assert rejection is not None
