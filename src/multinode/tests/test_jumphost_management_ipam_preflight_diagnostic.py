"""No-host checks before extending management attachments to multiple segments."""
from copy import deepcopy

import pytest

from tests.test_jumphost_host import world
from dnlab_multinode.services.jumphost_host import JumphostError


@pytest.mark.parametrize('difference', ['subnet','ipam-driver'])
def test_jumphost_rejects_management_ipam_mismatch_before_birth(world,difference):
    environment, worker = world
    if difference == 'subnet':
        environment.management['IPAM']['Config'] = [{'Subnet':'198.18.9.0/24','Gateway':'198.18.9.1'}]
    else:
        environment.management['IPAM']['Driver'] = 'default'
    network = deepcopy(environment.management)
    rejected = False
    try: worker.operate('ensure',environment.cfg)
    except JumphostError: rejected = True
    mutations = [args for args in environment.calls if args[:2] in (['docker','create'],['docker','start']) or args[:3] == ['ip','link','add']]
    assert not mutations, 'incompatible management IPAM authorized container/veth creation: ' + repr([args[:3] for args in mutations])
    assert rejected
    assert not worker.path.exists() and environment.management == network
