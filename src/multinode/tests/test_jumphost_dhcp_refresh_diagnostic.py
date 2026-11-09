"""No-host integration diagnostics for the guarded jumphost DHCP asset."""
from unittest.mock import MagicMock

from dnlab_multinode.services import jumphost
from tests.test_jumphost_host import World, config


def test_refresh_updates_the_asset_actually_mounted_by_guard(topo_factory, tmp_path, monkeypatch):
    topo=topo_factory(name='breakout-alpha',nodes={});topo.mgmt.dhcp=True
    initial=jumphost.render_dhcp_config(topo,'192.0.2.53')
    cfg=config(topo.name);cfg['dhcp']=initial
    world=World(cfg);worker=world.worker(tmp_path/'journal')
    record=worker.operate('ensure',cfg)
    from tests.test_jumphost_dhcp import install_service
    install_service(worker)
    mounted=worker.dhcp_directory(record)/'options'
    monkeypatch.setattr(jumphost,'_guard',lambda client,lab,action,config=None:worker.operate(action,config))
    client=MagicMock()
    jumphost.refresh_dhcp_config(topo,client,cfg['name'],'192.0.2.54',generation=cfg['generation'])
    assert 'option:dns-server,192.0.2.54' in mounted.read_text()
    assert '192.0.2.53' not in mounted.read_text()


def test_refresh_does_not_signal_unqualified_container_by_name(topo_factory):
    topo=topo_factory(name='breakout-alpha',nodes={});topo.mgmt.dhcp=True
    client=MagicMock()
    # No original generation or nonce is provided by this legacy path.
    try:jumphost.refresh_dhcp_config(topo,client,'foreign-container','192.0.2.53')
    except RuntimeError:pass
    assert not client.upload_text.called,'Unqualified refresh overwrote a path before preflight'
    assert not client.run.called,'Unqualified refresh sent a command to the supplied name'
