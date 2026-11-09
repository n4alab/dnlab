"""Regression: a persisted name alone must not authorize RealNet teardown."""
import json
import re

from dnlab_multinode.models.state import RealNetState
from dnlab_multinode.services.realnet import destroy_realnets


class ForeignResourcesSSH:
    def __init__(self):
        self.links={name:{'ifname':name,'ifindex':index,'ifalias':'foreign-owner',
                          'linkinfo':{'info_kind':kind}}
                    for index,(name,kind) in enumerate([
                        ('br-persisted','bridge'),('vx-persisted','vxlan'),('vh-persisted','veth')],10)}
        self.container={'Id':'a'*64,'Name':'/router-persisted','Config':{'Labels':{'owner':'another-lab'}}}
        self.commands=[]
        self.mutations=[]

    def run(self,command,check=True):
        self.commands.append(command)
        if command.startswith('ip -j'):return json.dumps(list(self.links.values()))
        if command.startswith('docker inspect'):return json.dumps([self.container])
        if 'docker rm -f router-persisted' in command:
            self.mutations.append('foreign-container-removed');self.container=None
        for name in re.findall(r'ip link del ([A-Za-z0-9_-]+)',command):
            if name in self.links:
                self.mutations.append('foreign-link-removed:'+name);del self.links[name]
        if 'iptables -D' in command:self.mutations.append('firewall-delete-without-ownership-check')
        return ''


def test_realnet_teardown_preserves_foreign_resources_with_persisted_names():
    client=ForeignResourcesSSH()
    state=RealNetState(name='access',bridge='br-persisted',vxlan_id=3001,
                       hosts=['master'],router_container='router-persisted',
                       router_veth='vh-persisted',vxlan_ifaces={'master':['vx-persisted']},
                       resource_identities={})
    try:
        destroy_realnets('lab-a',{'master':client},[state])
    except RuntimeError:
        pass  # A refusal is valid, but it must precede every mutation.
    assert not client.mutations,client.mutations
    assert client.container is not None
    assert set(client.links)=={'br-persisted','vx-persisted','vh-persisted'}
