"""Persisted RealNet endpoint names cannot authorize moving foreign data ports."""
import copy
import shlex

import pytest

from dnlab_multinode.models.state import RuntimeLinkState
from dnlab_multinode.services import runtime_links


class ForeignEndpoint:
    def __init__(self):
        self.link={'ifname':'host-endpoint','ifindex':30,'ifalias':'foreign-owner',
                   'address':'02:00:00:00:00:30','master':'br-other','flags':['UP']}
        self.commands=[];self.mutations=[]

    def run(self,command,check=True):
        self.commands.append(command);argv=shlex.split(command)
        if argv[:4]==['ip','link','set','host-endpoint']:
            self.mutations.append(command)
            if argv[4]=='master':self.link['master']=argv[5]
            elif argv[4]=='nomaster':self.link.pop('master',None)
            elif argv[4]=='up':self.link['flags']=['UP']
        return ''


@pytest.mark.parametrize('operation',['create','delete'])
def test_realnet_link_refuses_foreign_endpoint_before_mutation(operation):
    client=ForeignEndpoint();before=copy.deepcopy(client.link)
    link=RuntimeLinkState(id='rn0',link_type='real_net',lab_name='lab',host_a='master',host_b='master',
        endpoint_a={'node':'r1','iface':'eth1'},endpoint_b={'real_net':'access'},
        host_endpoint_a='host-endpoint',host_endpoint_b='br-lab',container_a='clab-lab-r1')
    try:
        if operation=='create':runtime_links.create_link(link,{'master':client})
        else:runtime_links.delete_link(link,{'master':client},set_carriers=False)
    except RuntimeError:
        pass  # Ownership refusal is expected; unrelated resources must stay intact.
    assert client.link==before and not client.mutations,{
        'operation':operation,'before':before,'after':client.link,'mutations':client.mutations,
        'runtime_link_state':link.state}
