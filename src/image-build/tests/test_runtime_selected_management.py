import pytest
from runtime_selected_management import (selected_nic_args,selected_management_script,data_carrier_slots,validate_data_carrier_slot)


def args():
    mgmt=['-device','e1000,netdev=p00,mac=02:00:00:00:00:aa','-netdev','tap,id=p00,ifname=tap0,script=/etc/tc-tap-mgmt-ifup,downscript=no']
    data=[]
    for i in range(1,16):
        data += ['-device',f'e1000,netdev=p{i:02d},mac=02:00:00:00:01:{i:02x},bus=pci.1,addr=0x{i+1:x}','-netdev',f'tap,id=p{i:02d},ifname=tap{i},script=/etc/tc-tap-ifup,downscript=no']
    return mgmt,data


def rewrite(mgmt,data,slot):
    return selected_nic_args(mgmt,data,slot=slot,warm_ports=15,management_mac='02:00:00:00:00:aa',port0_mac='02:00:00:00:01:00')


@pytest.mark.parametrize('slot',[0,1,8,15])
def test_selected_slot_preserves_other_nics_and_reserves_carrier(slot):
    mgmt,data=args()
    new_mgmt,new_data=rewrite(mgmt,data,slot)
    if not slot:
        assert (new_mgmt,new_data)==(mgmt,data)
    else:
        assert 'mac=02:00:00:00:01:00' in new_mgmt[1]
        assert 'script=/etc/tc-tap-ifup,' in new_mgmt[3]
        for i in range(1,16):
            before,after=data[4*(i-1):4*i],new_data[4*(i-1):4*i]
            if i==slot:
                assert after[1]==before[1].replace(f'mac=02:00:00:00:01:{i:02x}','mac=02:00:00:00:00:aa')
                assert after[3]==before[3].replace('script=/etc/tc-tap-ifup,','script=/etc/tc-tap-mgmt-ifup,')
            else:
                assert after==before
    assert args()==(mgmt,data)
    assert len(data_carrier_slots(slot=slot,warm_ports=15))==15
    with pytest.raises(ValueError,match='management'):
        validate_data_carrier_slot(slot,slot=slot,warm_ports=15)
    for i in data_carrier_slots(slot=slot,warm_ports=15):
        assert validate_data_carrier_slot(i,slot=slot,warm_ports=15)==i


@pytest.mark.parametrize('slot',[-1,16,True,'1'])
def test_invalid_selection(slot):
    with pytest.raises(ValueError,match='profile'):rewrite(*args(),slot)


@pytest.mark.parametrize('change',['duplicate','missing','socket','wrong-tap','duplicate-field','mac-collision'])
def test_incompatible_or_ambiguous_inventory(change):
    mgmt,data=args()
    if change=='duplicate':data[1]=data[5]
    if change=='missing':data=data[:-4]
    if change=='socket':data[3]=data[3].replace('tap,','socket,')
    if change=='wrong-tap':data[3]=data[3].replace('ifname=tap1,','ifname=tap8,')
    if change=='duplicate-field':data[1]+=',netdev=p01'
    if change=='mac-collision':data[5]=data[5].replace('mac=02:00:00:00:01:02','mac=02:00:00:00:00:aa')
    with pytest.raises(ValueError):rewrite(mgmt,data,1)


def test_script_changes_exact_tap_tokens_only():
    script='ip link set tap0 up\nredirect dev tap0\n# tap01 and tap15 stay\n'
    assert selected_management_script(script,slot=8,warm_ports=15)==script.replace('tap0 up','tap8 up').replace('dev tap0\n','dev tap8\n')
    with pytest.raises(ValueError,match='anchor'):
        selected_management_script('no tap',slot=8,warm_ports=15)


def test_independent_port_zero_mac_required():
    with pytest.raises(ValueError,match='MAC'):
        selected_nic_args(*args(),slot=1,warm_ports=15,management_mac='02:00:00:00:00:aa')


def adapter(monkeypatch,tmp_path,slot='8'):
    from runtime_selected_management import install
    path=tmp_path/'management-ifup'
    class VIOS_vm:
        conn_mode='tc'
        mgmt_passthrough=True
        mgmt_intf='mgmt0'
        data_intf_prefix='eth'
        num_nics=15
        start_nic_eth_idx=1
        mgmt_mac='02:00:00:00:00:aa'
        data_calls=0
        def get_intf_mac(self,name):
            if name=='mgmt0':return self.mgmt_mac
            return f'02:00:00:00:01:{int(name[3:]):02x}'
        def create_tc_tap_mgmt_ifup(self):
            path.write_text('ip link set tap0 up\nredirect dev tap0\n')
        def gen_mgmt(self):
            self.create_tc_tap_mgmt_ifup()
            return args()[0]
        def gen_nics(self):
            self.data_calls+=1
            return args()[1]
    class VR:
        def __init__(self):self.vms=[VIOS_vm()];self.started=False
        def start(self):
            self.started=True
            return self.vms[0].gen_mgmt(),self.vms[0].gen_nics()
    install(VIOS_vm,VR,script_path=path)
    if slot is None:monkeypatch.delenv('DNLAB_RUNTIME_MGMT_SLOT',raising=False)
    else:monkeypatch.setenv('DNLAB_RUNTIME_MGMT_SLOT',slot)
    monkeypatch.setenv('DNLAB_WARM_PORTS','15')
    monkeypatch.setenv('DNLAB_RUNTIME_BOOT_WAIT','true')
    monkeypatch.setenv('CLAB_MGMT_MAC',VIOS_vm.mgmt_mac)
    return VR(),path


@pytest.mark.parametrize('slot',[0,1,8,15])
def test_installed_adapter_rewrites_before_qemu_and_rebuilds_on_restart(monkeypatch,tmp_path,slot):
    vr,path=adapter(monkeypatch,tmp_path,str(slot))
    assert vr.start()==rewrite(*args(),slot)
    assert vr.vms[0].data_calls==1
    assert f'tap{slot} up' in path.read_text()
    assert vr.start()==rewrite(*args(),slot)
    assert vr.vms[0].data_calls==2


def test_installed_adapter_without_opt_in_preserves_legacy(monkeypatch,tmp_path):
    vr,path=adapter(monkeypatch,tmp_path,None)
    assert vr.start()==args()
    assert vr.vms[0].data_calls==1
    assert 'tap0 up' in path.read_text()
    assert not hasattr(vr.vms[0],'dnlab_selected_management_slot')


@pytest.mark.parametrize('bad',['slot','oob-kind','multi-vm','mode','no-wait','mac','missing-eth0','wrong-warm'])
def test_adapter_rejects_invalid_profile_before_start(monkeypatch,tmp_path,bad):
    vr,path=adapter(monkeypatch,tmp_path)
    if bad=='slot':monkeypatch.setenv('DNLAB_RUNTIME_MGMT_SLOT','08')
    if bad=='oob-kind':vr.vms[0].__class__.__name__='N9KVM'
    if bad=='multi-vm':vr.vms.append(vr.vms[0])
    if bad=='mode':vr.vms[0].conn_mode='macvtap'
    if bad=='no-wait':monkeypatch.delenv('DNLAB_RUNTIME_BOOT_WAIT')
    if bad=='mac':monkeypatch.setenv('CLAB_MGMT_MAC','02:00:00:00:00:bb')
    if bad=='missing-eth0':
        original=vr.vms[0].get_intf_mac
        vr.vms[0].get_intf_mac=lambda name:None if name=='eth0' else original(name)
    if bad=='wrong-warm':monkeypatch.setenv('DNLAB_WARM_PORTS','8')
    with pytest.raises(ValueError):vr.start()
    assert not vr.started and not path.exists()
