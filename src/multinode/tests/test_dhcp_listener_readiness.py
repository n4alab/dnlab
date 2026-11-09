"""Readiness requires sockets held by the original daemon, not matching ports."""
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from dnlab_multinode.services import jumphost_host as module


@pytest.mark.parametrize('main,expected',[
    ('interface=eth1\ndhcp-range=set:m,192.0.2.0,static,12h\n',[('udp',67)]),
    ('interface=eth1\ndhcp-range=set:m,2001:db8::,static,64,12h\n',[('udp6',547)]),
    ('interface=eth1\nenable-ra\ndhcp-range=set:m,2001:db8::,static,64,12h\n',[('raw6',58),('udp6',547)]),
])
def test_profile_derives_required_dhcp_listeners_and_ra(main,expected):
    assert module.dhcp_listener_requirements(main)==(['eth1'],expected)


@pytest.mark.parametrize('main',[
    'interface=eth0\ndhcp-range=192.0.2.0,static,12h\n',
    'interface=lo\ndhcp-range=192.0.2.0,static,12h\n',
    'interface=eth1\ninterface=eth1\ndhcp-range=192.0.2.0,static,12h\n',
    'dhcp-range=192.0.2.0,static,12h\n','interface=eth1\n',
    'interface=eth1\ndhcp-range=192.0.2.1,192.0.2.20,12h\n',
    'interface=eth1\ndhcp-range=2001:db8::,static,129,12h\n',
    'interface=eth1\nenable-ra\ndhcp-range=192.0.2.0,static,12h\n',
    'interface=eth1\ndhcp-range=192.0.2.0,static,12h\ndhcp-alternate-port=1067,1068\n',
])
def test_unqualified_profiles_are_refused(main):
    with pytest.raises(module.JumphostError,match='listener profile'):module.dhcp_listener_requirements(main)


@pytest.fixture
def inventory(monkeypatch):
    service=module.DHCPHostService(None,{},0);service.open=lambda *a,**kw:100
    state={'inode':111,'port':'0043','address':'00000000','remote':'00000000:0000','status':'07','uid':'0',
           'target':'socket:[111]','header':'sl local_address rem_address st tx_queue rx_queue','reads':0}
    def table(path,proc):
        state['reads']+=1
        if state.get('permission'):raise PermissionError('proc table denied')
        addr=state['address'] if path=='net/udp' else state['address']*4
        return state['header']+'\n'+f"0: {addr}:{state['port']} {state['remote']} {state['status']} 0:0 00:0 0 {state['uid']} 0 {state['inode']} 2 0 0\n"
    service.read=table
    monkeypatch.setattr(module.os,'listdir',lambda fd:['0','1','non-numeric'])
    monkeypatch.setattr(module.os,'readlink',lambda name,dir_fd:state['target'] if name=='0' else '/run/file')
    return service,state


def test_owned_wildcard_socket_qualifies_without_queue_or_timer_comparison(inventory):
    service,state=inventory
    assert service.listener_inventory({'host_pid':123},[('udp',67)])==[
        {'table':'udp','port':67,'inode':111,'uid':0,'address':'00000000'}]


@pytest.mark.parametrize('conflict',['inode','port','loopback','remote','state','bad-address','permission','schema','uid'])
def test_other_sockets_or_unreadable_tables_do_not_establish_readiness(inventory,conflict):
    service,state=inventory
    if conflict=='inode':state['inode']=222
    if conflict=='port':state['port']='0035'
    if conflict=='loopback':state['address']='0100007F'
    if conflict=='remote':state['remote']='0100007F:0044'
    if conflict=='state':state['status']='01'
    if conflict=='bad-address':state['address']='invalid!'
    if conflict=='permission':state['permission']=True
    if conflict=='schema':state['header']='unexpected'
    if conflict=='uid':state['uid']='-1'
    with pytest.raises((module.JumphostError,PermissionError)):
        service.listener_inventory({'host_pid':123},[('udp',67)])


def test_socket_replaced_during_inspection_is_refused(inventory,monkeypatch):
    service,state=inventory;calls=[0]
    def link(name,dir_fd):
        if name!='0':return '/run/file'
        calls[0]+=1;return 'socket:[111]' if calls[0]==1 else 'socket:[222]'
    monkeypatch.setattr(module.os,'readlink',link)
    with pytest.raises(module.JumphostError,match='generation changed'):
        service.listener_inventory({'host_pid':123},[('udp',67)])


def test_readiness_qualifies_all_attachments_and_original_process_twice():
    expected={'host_pid':123,'operation_nonce':'a'*32}
    record={'config':{'attachment':{'interface':'eth1','segment':'default'}},'dhcp_assets':{'files':{
        'main':{'content':'interface=eth1\ndhcp-range=192.0.2.0,static,12h\n'},
        'hosts':{'content':''},'options':{'content':''}}}}
    worker=SimpleNamespace(dhcp_preflight=Mock(),extension_rows=Mock(return_value={}))
    service=module.DHCPHostService(worker,record,0);service.observe=Mock(return_value=expected)
    service.listener_inventory=Mock(return_value=[{'inode':123}])
    proof=service.readiness(expected)
    assert proof['level']=='dhcp-listeners' and not proof['packet_readiness_verified']
    assert service.observe.call_count==worker.dhcp_preflight.call_count==2
    assert set(proof['configuration_sha256'])=={'main','hosts','options'}
    record['config']['attachment']['interface']='other'
    with pytest.raises(module.JumphostError,match='not qualified'):service.readiness(expected)


@pytest.mark.parametrize('table,port',[('udp6',547),('raw6',58)])
def test_ipv6_dhcp_and_ra_require_their_own_socket_inodes(inventory,table,port):
    service,state=inventory;state['port']=f'{port:04X}';state['remote']='0'*32+':0000'
    assert service.listener_inventory({'host_pid':123},[(table,port)])[0]['table']==table


def test_proxy_only_profile_has_dns_bindings_without_dhcp_or_ra():
    main='interface=eth1\nno-dhcp-interface=eth1\nport=53\nno-resolv\nserver=10.100.0.2\nlisten-address=192.0.2.254\nlisten-address=2001:db8::fe\n'
    assert module.dhcp_listener_requirements(main)==(['eth1'],[])
    bindings=module.dns_listener_bindings(main)
    assert len(bindings)==4 and {r[:2] for r in bindings}=={('udp',53),('tcp',53),('udp6',53),('tcp6',53)}
    assert ('udp',53,'fe0200c0') in bindings
    assert ('tcp6',53,'b80d01200000000000000000fe000000') in bindings


@pytest.mark.parametrize('table,state',[('udp','07'),('tcp','0A')])
def test_dns_proxy_requires_socket_owned_by_daemon_on_exact_address(inventory,table,state):
    service,row=inventory;row.update(port='0035',address='FE0200C0',status=state)
    # inventory fixture normally repeats non-UDP IPv6 addresses; use an IPv4 table here.
    original=service.read
    service.read=lambda name,proc:original('net/udp',proc)
    bindings=[(table,53,'fe0200c0')]
    assert service.listener_inventory({'host_pid':123},[(table,53)],bindings=bindings)[0]['address']=='fe0200c0'
    row['address']='0100007F'
    with pytest.raises(module.JumphostError):service.listener_inventory({'host_pid':123},[(table,53)],bindings=bindings)
    row.update(address='FE0200C0',inode=222)
    with pytest.raises(module.JumphostError):service.listener_inventory({'host_pid':123},[(table,53)],bindings=bindings)


@pytest.mark.parametrize('change',['missing-static','foreign-static','duplicate-static','missing-address','wildcard-address','duplicate-address','missing-upstream'])
def test_proxy_only_profile_refuses_incomplete_or_foreign_bindings(change):
    main='interface=eth1\nno-dhcp-interface=eth1\nport=53\nno-resolv\nserver=10.100.0.2\nlisten-address=192.0.2.254\n'
    if change=='missing-static':main=main.replace('no-dhcp-interface=eth1\n','')
    if change=='foreign-static':main=main.replace('no-dhcp-interface=eth1','no-dhcp-interface=other')
    if change=='duplicate-static':main+='no-dhcp-interface=eth1\n'
    if change=='missing-address':main=main.replace('listen-address=192.0.2.254\n','')
    if change=='wildcard-address':main=main.replace('192.0.2.254','0.0.0.0')
    if change=='duplicate-address':main+='listen-address=192.0.2.254\n'
    if change=='missing-upstream':main=main.replace('server=10.100.0.2\n','')
    with pytest.raises(module.JumphostError):module.dhcp_listener_requirements(main)
