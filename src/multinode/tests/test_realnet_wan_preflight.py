"""Diagnostic evidence: shared WAN infrastructure mismatch is not refused."""
from types import SimpleNamespace
import pytest
from dnlab_multinode.services.realnet_wan_host import WANError

from dnlab_multinode.models.topology import RealNetInfraCfg
from dnlab_multinode.services.realnet import ensure_realnet_wan_network


def test_unqualified_existing_wan_is_refused_without_mutation():
    cfg=RealNetInfraCfg();foreign_subnet='203.0.113.0/24'
    assert cfg.ipv4_subnet!=foreign_subnet
    class Client:
        def __init__(self):self.inspections=[];self.mutations=[]
        def run_no_check(self,command):
            self.inspections.append(command);return 0,foreign_subnet,''
        def run(self,command):self.mutations.append(command)
    client=Client()
    with pytest.raises(WANError):ensure_realnet_wan_network(client,SimpleNamespace(realnet_infra=cfg))
    assert len(client.mutations)==1 and client.mutations[0].startswith('python3 -c ')
    assert not any(command.startswith('docker network create') for command in client.mutations)
