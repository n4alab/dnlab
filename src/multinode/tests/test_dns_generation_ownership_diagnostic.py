"""Record unsafe commands without executing Docker, SSH or file mutations."""
import json
from unittest.mock import MagicMock

from dnlab_multinode.services import dns


def foreign_client():
    client = MagicMock()
    foreign = {'Id': 'f' * 64, 'Name': '/dnlab-lab-dns',
               'Config': {'Labels': {'owner': 'another-service'}},
               'State': {'Running': True}}
    def inspect(command, *args, **kwargs):
        if command.startswith('docker image inspect'):
            return 0, '', ''
        return 0, json.dumps([foreign]), ''
    client.run_no_check.side_effect = inspect
    client.run.return_value = ''
    return client


def test_dns_deploy_preserves_unqualified_existing_container(topo_factory, monkeypatch):
    client = foreign_client()
    monkeypatch.setattr(dns, 'collect_hosts_entries', lambda *args: [])
    monkeypatch.setattr(dns, 'get_upstream_dns', lambda *args: ['192.0.2.53'])
    monkeypatch.setattr(dns, 'ensure_jumphost_network', lambda *args: None)
    monkeypatch.setattr(dns, 'allocate_jumphost_ip', lambda *args: '10.100.0.2/24')
    try:
        dns.deploy_dns(topo_factory(name='lab'), client, {'master': client})
    except RuntimeError:
        pass
    deletes = [call.args[0] for call in client.run.call_args_list
               if call.args and call.args[0].startswith('docker rm')]
    assert deletes == [], f'Deploy removes unqualified container by name: {deletes}'


def test_dns_destroy_preserves_unqualified_existing_container_and_hosts_file():
    client = foreign_client()
    try:
        dns.destroy_dns('lab', client)
    except RuntimeError:
        pass
    mutations = [call.args[0] for call in client.run.call_args_list
                 if call.args and call.args[0].startswith(('docker rm', 'rm -f'))]
    assert mutations == [], f'Teardown removes unqualified resources: {mutations}'
