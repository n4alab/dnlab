import ast
from patches import _common
from test_warm_links_patch import VRNETLAB_SAMPLE


def source():
    text=VRNETLAB_SAMPLE.replace('class VM:\n','class VM:\n    def gen_mgmt(self): pass\n    def create_tc_tap_mgmt_ifup(self): pass\n')
    text,ok=_common.patch_warm_links(text)
    assert ok
    return text+'\n# dnlab-patched: runtime-management-v1\n'


def test_selected_patch_compiles_and_is_idempotent():
    before=source()
    patched,ok=_common.patch_runtime_selected_management(before)
    assert ok
    ast.parse(patched)
    assert _common.patch_runtime_selected_management(patched)==(patched,True)
    assert patched.index('_dnlab_install_selected_management(VM, VR)') > patched.index('VR.start = _dnlab_vr_start')


def test_missing_warm_or_stable_contract_cannot_enable_selection():
    for marker in ['# dnlab-patched: warm-links-v1','# dnlab-patched: runtime-management-v1']:
        before=source().replace(marker,'')
        assert _common.patch_runtime_selected_management(before)==(before,False)


def test_data_carrier_guard_runs_before_monitor_mutation():
    patched,ok=_common.patch_runtime_selected_management(source())
    assert ok
    function=next(n for n in ast.walk(ast.parse(patched)) if isinstance(n,ast.FunctionDef) and n.name=='set_link')
    calls=[]
    namespace={'_re':__import__('re'),'vm':type('VM',(),{'dnlab_selected_management_slot':8})(), 'warm_ports':15,'wait_monitor':lambda **kw:calls.append('wait')}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'selected-set-link.py','exec'),namespace)
    import pytest
    with pytest.raises(ValueError,match='management'):
        namespace['set_link']('eth8','down')
    assert calls==[]


def test_initial_carrier_excludes_selected_slot_and_restores_port_zero_to_data():
    patched,ok=_common.patch_runtime_selected_management(source())
    assert ok
    tree=ast.parse(patched)
    controller=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_dnlab_warm_link_controller')
    initial=next(n for n in ast.walk(controller) if isinstance(n,ast.With) and any(isinstance(b,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='selected_slot' for t in b.targets) for b in n.body))
    for slot in (None,0,1,8,15):
        calls=[]
        vm=type('VM',(),{})()
        if slot is not None:vm.dnlab_selected_management_slot=slot
        namespace={'vm':vm,'warm_ports':15,'monitor_command':calls.append}
        exec(compile(ast.Module(body=initial.body,type_ignores=[]),'selected-carrier-init.py','exec'),namespace)
        expected=range(1,16) if slot is None else [i for i in range(16) if i!=slot]
        assert calls==[f'set_link p{i:02d} off' for i in expected]
