"""A failed router veth create must never move an existing host interface."""
import shlex

from dnlab_multinode.models.state import RealNetState
from dnlab_multinode.models.topology import RealNet
from dnlab_multinode.services.realnet import deploy_router


class HostWithExistingEth1:
    def __init__(self):
        self.interfaces={'eth1':{'ifindex':30,'owner':'host-infrastructure','namespace':'host'}}
        self.commands=[];self.failures=[]

    def run_no_check(self,command,**kwargs):
        self.commands.append(command);return 0,'',''

    def run(self,command,**kwargs):
        self.commands.append(command)
        if '.State.Pid' in command:return '1234'
        if '.NetworkSettings.Networks' in command:return '198.18.0.2'
        # Model the existing shell recipe's semantics: without errexit, an
        # earlier failure does not prevent subsequent semicolon commands.
        for statement in command.split(';'):
            args=shlex.split(statement)
            if args[:3]==['ip','link','add'] and 'peer' in args:
                host=args[3];peer=args[args.index('peer')+2]
                if host in self.interfaces or peer in self.interfaces:
                    self.failures.append('veth create failed: interface name exists')
                else:
                    self.interfaces[host]={'owner':'fixture-veth','namespace':'host'}
                    self.interfaces[peer]={'owner':'fixture-veth','namespace':'host'}
            if args[:3]==['ip','link','set'] and len(args)>5 and args[4]=='netns':
                name=args[3]
                if name in self.interfaces:self.interfaces[name]['namespace']=args[5]
        return ''


def test_router_bootstrap_never_moves_preexisting_host_eth1(topo_factory):
    topo=topo_factory(num_workers=0)
    rn=RealNet(name='access',ipv4='192.0.2.1/24')
    state=RealNetState(name='access',bridge='br-realnet',vxlan_id=42001,
                       hosts=['master'],router_container='router-fixture',router_veth='vh-realnet')
    client=HostWithExistingEth1()
    try:deploy_router(topo,rn,state,client)
    except RuntimeError:pass  # Refusal before moving any foreign interface is valid.
    assert client.interfaces['eth1']=={'ifindex':30,'owner':'host-infrastructure','namespace':'host'},client.interfaces
