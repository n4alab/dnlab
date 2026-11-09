"""Stateful fake Engine/kernel, used to inject failures across side effects."""

from copy import deepcopy
from contextlib import contextmanager

from dnlab_runtime.manifest import RuntimeErrorBase


class FakeDocker:
    def __init__(self):
        self.containers = {}
        self.calls = []
        self.resist_term = False
        self.hook = lambda event: None
        self.networks = {"mgmt": {"Id":"mgmt-id","Name":"mgmt","Driver": "dnlab-vrf", "EnableIPv6": True, "IPAM": {"Driver": "dnlab-vrf", "Config":[{"Subnet":"192.0.2.0/24","Gateway":"192.0.2.1"},{"Subnet":"2001:db8::/64","Gateway":"2001:db8::1"}]}, "Labels": {"io.dnlab.lab": "demo", "io.dnlab.managed": "mgmt-vrf"}}}

    def inspect(self, name):
        return deepcopy(self.containers.get(name))

    def network(self, name):
        if name not in self.networks:
            raise RuntimeErrorBase("network missing")
        return deepcopy(self.networks[name])

    def create(self, name, config):
        self.calls.append(("create", name))
        if name in self.containers:
            raise RuntimeErrorBase("duplicate name")
        networks = {}
        for network, item in config.get("NetworkingConfig", {}).get("EndpointsConfig", {}).items():
            network=next((name for name,value in self.networks.items() if value['Id']==network),network)
            networks[network] = {"NetworkID":self.networks[network]["Id"],"IPAddress": item["IPAMConfig"]["IPv4Address"], "GlobalIPv6Address": item["IPAMConfig"]["IPv6Address"]}
            if 'MacAddress' in item:networks[network]['MacAddress']=item['MacAddress']
        self.containers[name] = {"Id": f"container-{len(self.calls)}", "Config": deepcopy(config), "State": {"Running": False, "Pid": 0}, "NetworkSettings": {"Networks": networks, "Ports": config["HostConfig"]["PortBindings"]}}
        self.hook("create")
        return {"Id": self.containers[name]["Id"]}

    def find(self, identity):
        return next(c for c in self.containers.values() if c["Id"] == identity)

    def start(self, identity):
        self.calls.append(("start", identity))
        self.find(identity)["State"] = {"Running": True, "Pid": 100}
        self.hook("start")

    def signal(self, identity, signal):
        self.calls.append(("signal", signal))
        if signal == "SIGKILL" or not self.resist_term:
            self.find(identity)["State"]["Running"] = False
        self.hook("signal")

    def remove(self, identity):
        self.calls.append(("remove", identity))
        name = next(n for n, c in self.containers.items() if c["Id"] == identity)
        if self.containers[name]["State"]["Running"]:
            raise RuntimeErrorBase("remove running")
        del self.containers[name]
        self.hook("remove")


class FakeLinux:
    def network_identity(self):
        return {'boot_id':'11111111-1111-1111-1111-111111111111','device':1,'inode':2}

    def namespace_identity(self, namespace):
        return {'device':1,'inode':namespace}

    def __init__(self):
        self.links = {}
        self.commands = []
        self.counter = 1
        self.hook = lambda args: None

    @contextmanager
    def namespace(self, pid):
        yield pid

    def move(self, name, namespace):
        return self.command(["link", "set", name, "netns", str(namespace)])

    def link(self, name, pid=None):
        return deepcopy(self.links.get((pid, name)))

    def delete_link(self, expected):
        current=next((value for (pid,_),value in self.links.items() if pid is None and value['ifindex']==expected['ifindex']),None)
        if current is None:return
        if current!=expected:raise RuntimeErrorBase('endpoint identity changed')
        return self.command(['link','delete',current['ifname']])

    def command(self, args, pid=None):
        self.commands.append((pid, args))
        if args==['-j','-d','link','show']:
            import json
            return json.dumps([v for (ns,_),v in self.links.items() if ns==pid])
        if args[:2] == ["link", "add"]:
            name, peer = args[2], args[args.index("peer") + 2]
            left, right = self.counter, self.counter + 1
            self.counter += 2
            self.links[(None, name)] = {"ifname": name, "ifindex": left, "link_index": right}
            if "alias" in args:
                self.links[(None, name)]["ifalias"] = args[args.index("alias") + 1]
            self.links[(None, peer)] = {"ifname": peer, "ifindex": right, "link_index": left}
            for pair_name in (name,peer):self.links[(None,pair_name)]['linkinfo']={'info_kind':'veth'}
            if "address" in args:
                self.links[(None, name)]["address"] = args[args.index("address") + 1]
                tail = args[args.index("peer") + 1:]
                if "address" in tail:
                    self.links[(None, peer)]["address"] = tail[tail.index("address") + 1]
        elif args[:2] == ["link", "delete"]:
            removed = self.links.pop((pid, args[2]), None)
            if removed:
                for key, value in list(self.links.items()):
                    if value["ifindex"] == removed["link_index"]:
                        del self.links[key]
        elif args[:2] == ["link", "set"]:
            key = (pid, args[2])
            value = self.links[key]
            if args[3] == "alias":
                value["ifalias"] = args[4]
            elif args[3] == "netns":
                self.links[(int(args[4]), args[2])] = self.links.pop(key)
            elif args[3] == "name":
                value["ifname"] = args[4]
                self.links[(pid, args[4])] = self.links.pop(key)
            elif args[3] == "mtu":
                value["mtu"] = int(args[4])
            elif args[3] == "up":
                value["flags"] = ["UP"]
        self.hook(args)


class FakeClock:
    def __init__(self):
        self.now = 0

    def clock(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


def seed_birth(journal,request,spec,container):
    """Explicit birth evidence for fixtures that synthesize committed nodes."""
    import uuid
    from dnlab_runtime.backend import LABEL
    from dnlab_runtime.manifest import fingerprint
    creator='fixture-birth-'+uuid.uuid4().hex;nonce=uuid.uuid4().hex
    container['Config']['Labels'].update({LABEL+'.creator':creator,LABEL+'.birth':nonce})
    journal.db.execute('INSERT INTO workload_generations VALUES(?,?,?,?,?,?,?,?,?,?)',
        (request['lab_id'],request['node_id'],1,creator,nonce,fingerprint(spec),container['Id'],'running',1,spec['container_name']))


def planned_request(engine,request):
    """Mirror a caller retaining the exact read-only plan observation."""
    if request['action']!='start' or 'management_preflight' in request:return request
    from dnlab_runtime.management_authority import effective
    if effective(engine.journal,request,request['spec']) is None:return request
    plan=engine.plan(request)
    proof=plan.get('management_preflight')
    return {**request,'management_preflight':proof} if proof is not None else request
