"""Pure service/config rendering; no account, package or systemd observations."""
import configparser
from copy import deepcopy
import os
import shlex
import subprocess

import pytest

from dnlab_runtime.libvirt_service_profile import render_profile, ROLES
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def request_profile():
    session=dict(host_id='master',uid=1001,gid=1002,uri='qemu:///session',
        socket='/run/dnlab-libvirt/libvirt/libvirt-sock',runtime_root='/run/dnlab-libvirt',
        state_root='/var/lib/dnlab-libvirt')
    return dict(session=session,libvirt_version='11.3.0-3+deb13u3',account_name='dnlab-libvirt',
        group_name='dnlab-libvirt',kvm_gid=108,layout_version=2,driver_config_root='/var/lib/dnlab-libvirt-control',
        binaries={role:dict(path='/usr/sbin/'+role,sha256=chr(ord('a')+index)*64)
                  for index,role in enumerate(ROLES)})


def test_rendering_has_no_host_io_and_preserves_explicit_inputs(request_profile,monkeypatch):
    def forbidden(*args,**kwargs):pytest.fail('profile rendering cannot perform host operations')
    monkeypatch.setattr(os,'open',forbidden)
    monkeypatch.setattr(subprocess,'run',forbidden)
    before=deepcopy(request_profile)
    profile=render_profile(**request_profile)
    assert request_profile==before and profile['qualified'] is False
    assert profile['session']==before['session'] and profile['binaries']==before['binaries']
    digest=profile.pop('profile_sha256')
    assert fingerprint(profile)==digest
    assert render_profile(**request_profile)['profile_sha256']==digest


def test_units_supervise_only_dedicated_foreground_daemons_without_force(request_profile):
    value=render_profile(**request_profile)
    for role in ROLES:
        path='/etc/systemd/system/dnlab-'+role+'.service'
        text=value['files'][path]['content']
        unit=configparser.ConfigParser(interpolation=None,strict=False);unit.read_string(text)
        service=unit['Service']
        assert service['User']=='1001' and service['Group']=='1002'
        assert service['Type']=='simple' and service['Restart']=='no'
        assert service['KillMode']=='process' and service['SendSIGKILL']=='no'
        assert service['CapabilityBoundingSet']=='' and service['NoNewPrivileges']=='yes'
        assert not unit.has_section('Install') and 'ExecStop' not in service
        assert 'RuntimeDirectory' not in service and 'StateDirectory' not in service
        command=shlex.split(service['ExecStart'])
        assert command==['/usr/sbin/'+role,'--config','/etc/dnlab/libvirt/'+role+'.conf',
                         '--pid-file','/run/dnlab-libvirt/libvirt/'+role+'.pid']

        environment=dict(line.removeprefix('Environment=').split('=',1)
                         for line in text.splitlines() if line.startswith('Environment='))
        assert environment['LIBVIRT_AUTOSTART']=='0'
        assert environment['XDG_RUNTIME_DIR']=='/run/dnlab-libvirt'
        assert environment['XDG_CONFIG_HOME']=='/var/lib/dnlab-libvirt-control'
        if role=='libvirtd':
            assert service['SupplementaryGroups']=='108'
            assert unit['Unit']['Requires']=='dnlab-virtlogd.service dnlab-virtlockd.service'
        else:assert 'PartOf' not in unit['Unit']


def test_proposed_package_and_file_inventory_excludes_implicit_networks(request_profile):
    value=render_profile(**request_profile)
    assert all(v['uid']==v['gid']==0 and v['mode']==0o644 for v in value['files'].values())
    assert len(value['files'])==7
    assert value['package_request']['install_recommends'] is False
    assert 'libvirt-daemon-plugin-lockd' in value['package_request']['roots']
    assert 'libvirt-daemon-system' not in value['package_request']['roots']
    assert 'libvirt-daemon-config-network' in value['package_request']['forbidden_new_packages']
    assert 'libvirt-guests.service' in value['forbidden_vendor_activation']
    assert value['client_environment']['LIBVIRT_DEFAULT_URI']=='qemu:///session'
    assert 'lock_manager = "lockd"' in value['files']['/var/lib/dnlab-libvirt-control/libvirt/qemu.conf']['content']
    assert 'listen_tcp = 0' in value['files']['/etc/dnlab/libvirt/libvirtd.conf']['content']
    assert all('/etc/libvirt/' not in path and '/run/libvirt/' not in path for path in value['files'])


@pytest.mark.parametrize('fault',['root-user','root-group','root-name','system-uri','shared-runtime','shared-state',
    'shared-config','modular-socket','specifier','command-injection','unknown-binary','missing-hash','version-injection','root-kvm'])
def test_unsafe_or_other_session_profiles_fail_without_fallback(request_profile,fault):
    if fault=='root-user':request_profile['session']['uid']=0
    elif fault=='root-group':request_profile['session']['gid']=0
    elif fault=='root-name':request_profile['account_name']='root'
    elif fault=='system-uri':request_profile['session']['uri']='qemu:///system'
    elif fault=='shared-runtime':
        request_profile['session'].update(runtime_root='/run/libvirt',socket='/run/libvirt/libvirt/libvirt-sock')
    elif fault=='shared-state':request_profile['session']['state_root']='/var/lib/libvirt'
    elif fault=='shared-config':request_profile['config_root']='/etc/libvirt'
    elif fault=='modular-socket':request_profile['session']['socket']='/run/dnlab-libvirt/libvirt/virtqemud-sock'
    elif fault=='specifier':request_profile['config_root']='/etc/dnlab-%n/libvirt'
    elif fault=='command-injection':request_profile['binaries']['libvirtd']['path']='/usr/sbin/libvirtd --listen'
    elif fault=='unknown-binary':request_profile['binaries']['libvirtd']['path']='/usr/sbin/virtqemud'
    elif fault=='missing-hash':request_profile['binaries']['libvirtd']['sha256']=''
    elif fault=='version-injection':request_profile['libvirt_version']='11.3\nchanged'
    else:request_profile['kvm_gid']=0
    with pytest.raises(TemplateError):render_profile(**request_profile)


def test_profile_digest_binds_binary_version_credentials_and_runtime_paths(request_profile):
    original=render_profile(**request_profile)
    request_profile['binaries']['libvirtd']['sha256']='f'*64
    assert render_profile(**request_profile)['profile_sha256']!=original['profile_sha256']
    request_profile['session']['uid']=1003
    changed=render_profile(**request_profile)
    assert changed['session']['uid']==1003 and original['session']['uid']==1001


def test_nonroot_qemu_driver_has_a_planned_writable_config_tree(request_profile):
    """Native session QEMU uses XDG_CONFIG_HOME/libvirt/qemu, not --config's path."""
    from pathlib import PurePosixPath
    profile=render_profile(**request_profile)
    config_tree=PurePosixPath(profile['client_environment']['XDG_CONFIG_HOME'])/'libvirt/qemu'
    planned=[directory for directory in profile['directories']
        if config_tree.is_relative_to(directory['path'])]
    assert planned, 'native QEMU configuration has no planned ancestor'
    nearest=max(planned,key=lambda directory:len(PurePosixPath(directory['path']).parts))
    uid=profile['session']['uid'];groups={profile['session']['gid'],request_profile['kvm_gid']}
    write=0o200 if nearest['uid']==uid else 0o020 if nearest['gid'] in groups else 0o002
    assert nearest['mode']&write, (
        f"non-root QEMU cannot write its native config tree {config_tree}; "
        f"planned ancestor {nearest['path']} is uid={nearest['uid']} gid={nearest['gid']} mode={nearest['mode']:04o}")


def test_native_qemu_config_is_at_lookup_path_and_cannot_be_replaced_by_session_uid(request_profile):
    from pathlib import PurePosixPath
    profile=render_profile(**request_profile)
    base=PurePosixPath(profile['client_environment']['XDG_CONFIG_HOME'])/'libvirt'
    qemu_conf=str(base/'qemu.conf')
    assert profile['schema_version']==2 and profile['driver_layout']==dict(
        config_base=str(base),qemu_config=qemu_conf,mutable_root=str(base/'qemu'))
    assert qemu_conf in profile['files'] and '/etc/dnlab/libvirt/qemu.conf' not in profile['files']
    assert profile['files'][qemu_conf]['uid']==0 and profile['files'][qemu_conf]['mode']==0o644
    parents=[d for d in profile['directories'] if PurePosixPath(qemu_conf).is_relative_to(d['path'])]
    assert {d['path'] for d in parents}=={str(base.parent),str(base)}
    assert all(d['uid']==d['gid']==0 and d['mode']==0o755 for d in parents)
    mutable=next(d for d in profile['directories'] if d['path']==str(base/'qemu'))
    assert mutable==dict(path=str(base/'qemu'),uid=1001,gid=1002,mode=0o700)
    assert not base.is_relative_to(profile['session']['state_root'])


@pytest.mark.parametrize('fault',['inside-state','above-state','shared','outside-varlib','nested-parent','missing-root','bad-version'])
def test_new_layout_never_places_root_config_in_session_writable_ancestors(request_profile,fault):
    if fault=='inside-state':request_profile['driver_config_root']=request_profile['session']['state_root']+'/driver'
    elif fault=='above-state':request_profile['session']['state_root']=request_profile['driver_config_root']+'/state'
    elif fault=='shared':request_profile['driver_config_root']='/var/lib/libvirt'
    elif fault=='outside-varlib':request_profile['driver_config_root']='/etc/dnlab/driver'
    elif fault=='nested-parent':request_profile['driver_config_root']='/var/lib/foreign-parent/driver'
    elif fault=='missing-root':del request_profile['driver_config_root']
    else:request_profile['layout_version']=True
    with pytest.raises(TemplateError):render_profile(**request_profile)


def test_historical_default_profile_is_byte_stable_and_not_installable(request_profile):
    from dnlab_runtime.libvirt_service_profile import require_installable
    from dnlab_runtime.manifest import Conflict
    request_profile.pop('layout_version');request_profile.pop('driver_config_root')
    historical=render_profile(**request_profile)
    assert historical['schema_version']==1
    assert historical['profile_sha256']=='1e3b1e5017af071e5a8e6361383eabcbf71e4734ea38b1d15bae1b3a13dc1d73'
    assert len(historical['directories'])==7 and 'driver_layout' not in historical
    with pytest.raises(Conflict,match='historical profile is readonly'):require_installable(historical)

def test_explicit_activation_does_not_pull_in_inactive_helper_units(request_profile):
    request_profile['activation_policy']='requisite-after-v1'
    profile=render_profile(**request_profile)
    config=configparser.ConfigParser(interpolation=None,strict=False)
    config.read_string(profile['files']['/etc/systemd/system/dnlab-libvirtd.service']['content'])
    helpers={'dnlab-virtlogd.service','dnlab-virtlockd.service'}
    pulled=set()
    for option in ('Requires','Wants','BindsTo','Upholds'):
        pulled.update(helpers.intersection(config['Unit'].get(option,'').split()))
    assert not pulled, 'starting libvirtd can implicitly start untracked helper generations: '+str(sorted(pulled))
    assert set(config['Unit']['Requisite'].split())==helpers
    assert set(config['Unit']['After'].split())==helpers


def test_version2_without_activation_policy_preserves_original_bytes(request_profile):
    from dnlab_runtime.libvirt_service_profile import require_activatable
    from dnlab_runtime.manifest import Conflict
    original=render_profile(**request_profile)
    assert original['profile_sha256']=='b60cb166a5866417cb98b82afdfb5b53dfc86414017162e5a5d88fe57741eb6b'
    with pytest.raises(Conflict,match='no implicit profile conversion'):require_activatable(original)
    changed=render_profile(**dict(request_profile,activation_policy='requisite-after-v1'))
    different=[path for path in original['files'] if original['files'][path]!=changed['files'][path]]
    assert different==['/etc/systemd/system/dnlab-libvirtd.service']
    assert original['directories']==changed['directories']
    require_activatable(changed)


@pytest.mark.parametrize('policy',['unknown',False,1])
def test_unknown_activation_policy_is_rejected(request_profile,policy):
    with pytest.raises(TemplateError):render_profile(**dict(request_profile,activation_policy=policy))
