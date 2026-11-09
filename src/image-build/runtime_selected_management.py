"""Experimental source-build helpers; not installed in candidate images yet."""
import re


def validate_slot(slot, warm_ports):
    if type(slot) is not int or type(warm_ports) is not int or not 1 <= warm_ports <= 15 or not 0 <= slot <= warm_ports:
        raise ValueError('selected management slot is outside the vIOS profile')


def _mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('invalid selected-slot MAC')
    if int(value[:2], 16) & 1 or value.lower() == '00:00:00:00:00:00':
        raise ValueError('selected-slot MAC must be unicast and nonzero')
    return value.lower()


def _pairs(args):
    if len(args) % 2:
        raise ValueError('unsupported QEMU NIC argument layout')
    result = []
    for index in range(0, len(args), 2):
        if args[index] not in {'-device', '-netdev'}:
            raise ValueError('unsupported QEMU NIC argument')
        parts, fields = args[index+1].split(','), {}
        for part in parts[1:]:
            if '=' not in part:
                raise ValueError('unsupported QEMU NIC field')
            key,value = part.split('=',1)
            if key in fields:
                raise ValueError('duplicated QEMU NIC field')
            fields[key] = value
        result.append((args[index],parts[0],fields))
    return result


def _render(pairs):
    return [item for option,driver,fields in pairs for item in (option, ','.join([driver,*[k+'='+v for k,v in fields.items()]]))]


def selected_nic_args(management_args, data_args, *, slot, warm_ports, management_mac, port0_mac=None):
    """Preserve slots/PCI identities and return p00 to data for nonzero selection.

    Caller must provision an independent eth0 and reserve the Docker uplink
    outside ethN before releasing QEMU. Only the qualified single-VM TC profile
    is supported; this helper does not qualify guest traffic or image identity.
    """
    validate_slot(slot,warm_ports)
    management_mac = _mac(management_mac)
    management,data = _pairs(management_args),_pairs(data_args)
    devices,backends = {},{}
    for option,driver,fields in management+data:
        key = fields.get('netdev' if option == '-device' else 'id')
        inventory = devices if option == '-device' else backends
        if not key or key in inventory:
            raise ValueError('absent or duplicated QEMU slot')
        inventory[key] = (driver,fields)
    expected = {f'p{i:02d}' for i in range(warm_ports+1)}
    if set(devices) != expected or set(backends) != expected or len(management) != 2 or {f.get('netdev',f.get('id')) for _,_,f in management} != {'p00'}:
        raise ValueError('QEMU inventory differs from the qualified vIOS profile')
    for i in range(warm_ports+1):
        driver,fields = backends[f'p{i:02d}']
        script = '/etc/tc-tap-mgmt-ifup' if i == 0 else '/etc/tc-tap-ifup'
        if driver != 'tap' or fields != {'id':f'p{i:02d}','ifname':f'tap{i}','script':script,'downscript':'no'}:
            raise ValueError('selected management requires the qualified TC tap backend')
        _mac(devices[f'p{i:02d}'][1].get('mac'))
    if devices['p00'][1]['mac'].lower() != management_mac:
        raise ValueError('legacy management MAC differs from the stable port')
    if slot:
        devices['p00'][1]['mac'] = _mac(port0_mac)
        devices[f'p{slot:02d}'][1]['mac'] = management_mac
        backends['p00'][1]['script'] = '/etc/tc-tap-ifup'
        backends[f'p{slot:02d}'][1]['script'] = '/etc/tc-tap-mgmt-ifup'
    macs = [_mac(fields['mac']) for _,fields in devices.values()]
    if len(set(macs)) != len(macs):
        raise ValueError('selected management duplicates another NIC MAC')
    return _render(management),_render(data)


def selected_management_script(script, *, slot, warm_ports):
    validate_slot(slot,warm_ports)
    if not re.search(r'\btap0\b',script):
        raise ValueError('management TC script has no legacy tap anchor')
    return re.sub(r'\btap0\b',f'tap{slot}',script)


def data_carrier_slots(*, slot, warm_ports):
    validate_slot(slot,warm_ports)
    return tuple(i for i in range(warm_ports+1) if i != slot)


def validate_data_carrier_slot(index, *, slot, warm_ports):
    if type(index) is not int or index not in data_carrier_slots(slot=slot,warm_ports=warm_ports):
        raise ValueError('carrier request targets management or an absent data slot')
    return index


def install(vm_class, vr_class, *, script_path='/etc/tc-tap-mgmt-ifup'):
    """Install the opt-in ABI in source-built, single-VM vIOS candidates."""
    import os
    from pathlib import Path

    original_mgmt = vm_class.gen_mgmt
    original_data = vm_class.gen_nics
    original_script = vm_class.create_tc_tap_mgmt_ifup
    original_start = vr_class.start

    def start(self):
        raw = os.environ.get('DNLAB_RUNTIME_MGMT_SLOT')
        if raw is not None:
            if not re.fullmatch(r'0|[1-9][0-9]*', raw):
                raise ValueError('invalid DNLAB_RUNTIME_MGMT_SLOT')
            slot = int(raw)
            validate_slot(slot, 15)
            if len(self.vms) != 1 or type(self.vms[0]).__name__ != 'VIOS_vm':
                raise ValueError('selected management requires the single-VM vIOS adapter')
            vm = self.vms[0]
            if (vm.conn_mode != 'tc' or not vm.mgmt_passthrough or vm.mgmt_intf != 'mgmt0'
                    or vm.data_intf_prefix != 'eth' or vm.num_nics != 15 or vm.start_nic_eth_idx != 1
                    or os.environ.get('DNLAB_WARM_PORTS') != '15'
                    or os.environ.get('DNLAB_WARM_VM_INDEX', '0') != '0'
                    or os.environ.get('DNLAB_RUNTIME_BOOT_WAIT', '').lower() != 'true'):
                raise ValueError('selected management requires the prepared vIOS TC/warm profile')
            stable_mac = _mac(os.environ.get('CLAB_MGMT_MAC'))
            if _mac(vm.get_intf_mac('mgmt0')) != stable_mac:
                raise ValueError('selected management stable interface MAC differs')
            # Every data slot, including the former p00, needs an independent
            # endpoint. The runtime reserves the selected endpoint from links.
            for index in range(0 if slot else 1, 16):
                _mac(vm.get_intf_mac(f'eth{index}'))
            vm.dnlab_selected_management_slot = slot
        return original_start(self)

    def script(self):
        result = original_script(self)
        slot = getattr(self, 'dnlab_selected_management_slot', None)
        if slot is not None:
            path = Path(script_path)
            path.write_text(selected_management_script(path.read_text(), slot=slot, warm_ports=15))
        return result

    def management(self):
        slot = getattr(self, 'dnlab_selected_management_slot', None)
        if slot is None:
            return original_mgmt(self)
        management_args = original_mgmt(self)
        data_args = original_data(self)
        management_args, self._dnlab_selected_data_args = selected_nic_args(
            management_args, data_args, slot=slot, warm_ports=15,
            management_mac=self.mgmt_mac,
            port0_mac=self.get_intf_mac('eth0') if slot else None)
        return management_args

    def data(self):
        if getattr(self, 'dnlab_selected_management_slot', None) is None:
            return original_data(self)
        if not hasattr(self, '_dnlab_selected_data_args'):
            raise ValueError('selected management requires gen_mgmt before gen_nics')
        return self._dnlab_selected_data_args

    vm_class.gen_mgmt = management
    vm_class.gen_nics = data
    vm_class.create_tc_tap_mgmt_ifup = script
    vr_class.start = start
