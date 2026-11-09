"""Routing prerequisites reject alternate gateways and policy shortcuts."""
from copy import deepcopy
from contextlib import nullcontext
import ipaddress
import json

import pytest

from dnlab_multinode.services.management_routing_observation import validate
from dnlab_multinode.services.jumphost_host import JumphostError
from dnlab_multinode.services import management_service_runtime as transport
from tests.test_management_service_host import runtime


def observation(attachments=None, external=None):
    attachments=attachments or {
        'default':{'interface':'eth1','ipv4':'198.18.1.254/24','ipv6':'2001:db8:1::ffff/64'},
        'blue':{'interface':'jmblue','ipv4':'198.18.2.254/24','ipv6':'2001:db8:2::ffff/64'}}
    external=external or {'subnet':'198.19.245.0/24','gateway':'198.19.245.1','ip':'198.19.245.3'}
    routes={'4':[{'dst':'default','dev':'eth0','gateway':external['gateway']}], '6':[]}
    for row in list(attachments.values())+[{'interface':'eth0','ipv4':external['ip']+'/24','ipv6':''}]:
        for version,key in ((4,'ipv4'),(6,'ipv6')):
            if row[key]:
                address=ipaddress.ip_interface(row[key])
                route={'dst':str(address.network),'dev':row['interface'],'protocol':'kernel'}
                if version==4:route['prefsrc']=str(address.ip)
                routes[str(version)].append(route)
        routes['6'].append({'dst':'fe80::/64','dev':row['interface'],'protocol':'kernel'})
    rules={str(v):[{'priority':p,'src':'all','table':t} for p,t in
        ([(0,'local'),(32766,'main')]+([(32767,'default')] if v==4 else []))] for v in (4,6)}
    return attachments,external,{'ipv4':'1','ipv6':'1'},routes,rules


def test_two_l2_paths_are_prerequisites_and_never_packet_readiness():
    values=observation();before=deepcopy(values)
    result=validate(*values)
    assert values==before
    assert result['connected_prefixes']['6']==['2001:db8:1::/64','2001:db8:2::/64']
    assert result['packet_forwarding_verified'] is False
    assert result['external_ipv6_verified'] is False


@pytest.mark.parametrize('fault',['ipv4-off','ipv6-off','wrong-port','gateway','source',
    'missing','duplicate','more-specific','multipath','ipv6-default','default-missing',
    'policy-table','policy-selector','extra-rule','foreign-link-local'])
def test_routing_conflicts_rejected_without_repair(fault):
    attachments,external,forwarding,routes,rules=values=observation()
    if fault in ('ipv4-off','ipv6-off'):forwarding[fault.split('-')[0]]='0'
    elif fault=='wrong-port':routes['4'][1]['dev']='jmblue'
    elif fault=='gateway':routes['4'][0]['gateway']='198.19.245.9'
    elif fault=='source':routes['4'][1]['prefsrc']='198.18.1.1'
    elif fault=='missing':routes['6'].pop(0)
    elif fault=='duplicate':routes['4'].append(deepcopy(routes['4'][1]))
    elif fault=='more-specific':routes['4'].append({'dst':'198.18.2.5/32','dev':'eth0','protocol':'static'})
    elif fault=='multipath':routes['4'][1]['nexthops']=[{'dev':'eth0'}]
    elif fault=='ipv6-default':routes['6'].append({'dst':'default','dev':'eth0','gateway':'fe80::1'})
    elif fault=='default-missing':routes['4'].pop(0)
    elif fault=='policy-table':rules['6'][1]['table']=123
    elif fault=='policy-selector':rules['4'][1]['fwmark']='0x1'
    elif fault=='extra-rule':rules['4'].insert(1,{'priority':100,'src':'all','table':100})
    elif fault=='foreign-link-local':routes['6'][-1]['dev']='foreign'
    before=deepcopy(values)
    with pytest.raises(ValueError):validate(*values)
    assert values==before


def test_ipv4_only_does_not_require_invented_ipv6_connectivity():
    attachments,external,*_=observation()
    for row in attachments.values():row['ipv6']=''
    assert validate(*observation(attachments,external))['connected_prefixes']['6']==[]


def test_service_snapshot_uses_verified_namespace_and_preserves_rejected_evidence(runtime,monkeypatch):
    worker,jw,dw,env,jump,dns,network=runtime;worker.apply()
    original=worker.observe();records=[v.path.read_bytes() for v in (jump,dns,network)]
    monkeypatch.setattr(worker,'observe',lambda:deepcopy(original))
    monkeypatch.setattr(jump,'namespace',lambda record:nullcontext(42))
    attachments={k:v['attachment'] for k,v in worker.intent['attachments'].items()}
    external=dict(jump.read()['config']['network'],ip=jump.read()['config']['ip'])
    _,_,forwarding,routes,rules=observation(attachments,external)
    forwarding['ipv6']='0';calls=[]
    def read(argv,**kw):
        assert argv[:2]==['nsenter','--net=/proc/self/fd/42'] and kw=={'pass_fds':(42,)}
        command=argv[2:];calls.append(command)
        if command[:2]==['sysctl','-n']:return forwarding['ipv4' if command[2]=='net.ipv4.ip_forward' else 'ipv6']+'\n'
        if command[:2]==['ip','-j']:
            assert command[3:] in (['route','show','table','main'],['rule','show'])
            return json.dumps((routes if command[3]=='route' else rules)[command[2][-1]])
        assert command in (['iptables-save'],['ip6tables-save'])
        return '*filter\n:FORWARD ACCEPT [0:0]\nCOMMIT\n'
    monkeypatch.setattr(jump,'run',read)
    result=worker.routing_snapshot()
    assert result['validation']['status']=='rejected'
    assert result['snapshot']['forwarding']['ipv6']=='0'
    assert result['snapshot']['routes']==routes and len(calls)==8
    assert result['functional_readiness_verified'] is False
    assert records==[v.path.read_bytes() for v in (jump,dns,network)]
    forwarding['ipv6']='1'
    assert worker.routing_snapshot()['validation']['status']=='accepted'
    observations=iter([original,dict(original,jumphost={'container_id':'foreign'})])
    monkeypatch.setattr(worker,'observe',lambda:next(observations))
    with pytest.raises(JumphostError,match='generation changed'):worker.routing_snapshot()


def test_standalone_transport_contains_same_validator_without_package_import():
    namespace={'__name__':'_test_routing_worker'}
    exec(transport.program(),namespace)
    assert namespace['validate_routing'](*observation())==validate(*observation())
