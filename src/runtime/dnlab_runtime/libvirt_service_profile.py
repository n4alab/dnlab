"""Pure rendering of a proposed dedicated monolithic libvirt service profile.

No account lookup, file IO, package action, systemd command or libvirt connection
is performed. A later installation transaction must qualify every target and
dependency before installing or starting these files. Binary hashes are inputs,
not proof that those binaries have been inspected or installed.
"""
from copy import deepcopy
import hashlib
from pathlib import PurePosixPath
import re

from .libvirt_session import DedicatedSession
from .libvirt_xml import absolute
from .manifest import Conflict, fingerprint
from .vm_template import digest, fields, require

ROLES = ('libvirtd', 'virtlogd', 'virtlockd')
PACKAGES = ('libvirt-daemon', 'libvirt-daemon-driver-qemu', 'libvirt-daemon-log',
            'libvirt-daemon-lock', 'libvirt-daemon-plugin-lockd', 'libvirt-clients')
EXPLICIT_ACTIVATION = 'requisite-after-v1'


def safe_path(value):
    absolute(value)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is not None,
            'service paths must not contain specifiers or command syntax')
    return value


def render_profile(session, *, libvirt_version, account_name, group_name, kvm_gid,
                   binaries, config_root='/etc/dnlab/libvirt', layout_version=1, driver_config_root=None,
                   activation_policy=None):
    session = DedicatedSession(session, lambda: None).profile
    require(all(isinstance(name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name)
                and name != 'root' for name in (account_name, group_name)), 'dedicated account names required')
    require(type(kvm_gid) is int and kvm_gid > 0, 'explicit non-root KVM group ID required')
    require(isinstance(libvirt_version, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+:~-]{0,127}', libvirt_version),
            'pinned libvirt package version required')
    runtime = safe_path(session['runtime_root']); state = safe_path(session['state_root'])
    config = safe_path(config_root)
    require(PurePosixPath(runtime).is_relative_to('/run') and len(PurePosixPath(runtime).parts) >= 3
            and PurePosixPath(state).is_relative_to('/var/lib') and len(PurePosixPath(state).parts) >= 4
            and PurePosixPath(config).is_relative_to('/etc') and len(PurePosixPath(config).parts) >= 4
            and runtime != '/run/libvirt' and state != '/var/lib/libvirt',
            'private runtime, state and config roots required')
    require(session['socket'] == runtime + '/libvirt/libvirt-sock'
            and PurePosixPath(config).name == 'libvirt', 'explicit monolithic session socket/config layout required')
    require(type(layout_version) is int and layout_version in (1, 2), 'explicit supported service layout required')
    require(activation_policy is None or activation_policy == EXPLICIT_ACTIVATION,
            'explicit supported service activation policy required')
    require(activation_policy is None or layout_version == 2,
            'explicit activation policy requires version 2 layout')
    driver_base = config
    if layout_version == 1:
        require(driver_config_root is None, 'historical layout cannot acquire new driver paths')
        xdg_config = str(PurePosixPath(config).parent)
    else:
        require(isinstance(driver_config_root, str), 'version 2 requires explicit private driver configuration root')
        xdg_config = safe_path(driver_config_root)
        driver_path = PurePosixPath(xdg_config)
        require(driver_path.parent == PurePosixPath('/var/lib')
                and xdg_config != '/var/lib/libvirt', 'private driver configuration root directly under /var/lib required')
        for other in (runtime, state, config):
            require(not driver_path.is_relative_to(other) and not PurePosixPath(other).is_relative_to(driver_path),
                    'driver configuration root must be separate from writable session and administrative roots')
        driver_base = xdg_config + '/libvirt'
    fields(binaries, ROLES, 'libvirt service binaries')
    for role, binary in binaries.items():
        fields(binary, ('path', 'sha256'), 'pinned service binary')
        safe_path(binary['path'])
        require(PurePosixPath(binary['path']).name == role and digest(binary['sha256']),
                'explicit daemon executable and hash required')
    require(len({value['path'] for value in binaries.values()}) == len(ROLES), 'distinct daemon binaries required')

    environment = {'XDG_RUNTIME_DIR': runtime, 'XDG_CONFIG_HOME': xdg_config,
        'XDG_DATA_HOME': state + '/data', 'XDG_CACHE_HOME': state + '/cache', 'LIBVIRT_AUTOSTART': '0'}
    files = {}
    def add(path, content):
        files[path] = {'content': content, 'sha256': hashlib.sha256(content.encode()).hexdigest(),
                       'uid': 0, 'gid': 0, 'mode': 0o644}
    for role in ROLES:
        unit = ['[Unit]', 'Description=dNLab dedicated ' + role]
        if role == 'libvirtd':
            dependency='Requisite' if activation_policy == EXPLICIT_ACTIVATION else 'Requires'
            unit.extend([dependency+'=dnlab-virtlogd.service dnlab-virtlockd.service',
                         'After=dnlab-virtlogd.service dnlab-virtlockd.service'])
        unit.extend(['', '[Service]', 'Type=simple', 'User=' + str(session['uid']),
                     'Group=' + str(session['gid']), 'UMask=0077'])
        if role == 'libvirtd':unit.append('SupplementaryGroups=' + str(kvm_gid))
        unit.extend('Environment=' + key + '=' + value for key, value in environment.items())
        unit.extend(['ExecStart=' + binaries[role]['path'] + ' --config ' + config + '/' + role + '.conf'
                     + ' --pid-file ' + runtime + '/libvirt/' + role + '.pid',
                     'KillMode=process', 'KillSignal=SIGTERM', 'SendSIGKILL=no',
                     'Restart=no', 'TimeoutStopSec=30s', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', ''])
        add('/etc/systemd/system/dnlab-' + role + '.service', '\n'.join(unit))
    add(config + '/libvirtd.conf', '# dNLab dedicated non-root session\n'
        'listen_tcp = 0\nlisten_tls = 0\nunix_sock_rw_perms = "0700"\nauth_unix_rw = "none"\n')
    add(driver_base + '/qemu.conf', '# Dedicated session: disks remain owned by runtime operations.\nlock_manager = "lockd"\n')
    for role in ('virtlogd', 'virtlockd'):
        add(config + '/' + role + '.conf', '# dNLab private ' + role + ': use qualified package defaults.\n')

    directories = [{'path': path, 'uid': session['uid'], 'gid': session['gid'], 'mode': 0o700}
        for path in (state, state + '/data', state + '/cache', runtime, runtime + '/libvirt')]
    directories.extend({'path': path, 'uid': 0, 'gid': 0, 'mode': 0o755}
        for path in (str(PurePosixPath(config).parent), config))
    if layout_version == 2:
        # Root-owned ancestors prevent the session user from replacing qemu.conf.
        directories.extend({'path': path, 'uid': 0, 'gid': 0, 'mode': 0o755}
            for path in (xdg_config, driver_base))
        directories.append({'path': driver_base + '/qemu', 'uid': session['uid'],
                            'gid': session['gid'], 'mode': 0o700})
    client = {**environment, 'LIBVIRT_DEFAULT_URI': 'qemu:///session'}
    result = {'schema_version': layout_version, 'profile': 'dedicated-libvirtd-session', 'qualified': False,
        'session': session, 'account': {'name': account_name, 'group': group_name,
            'uid': session['uid'], 'gid': session['gid'], 'home': state, 'interactive_login': False},
        'binaries': deepcopy(binaries), 'directories': directories, 'files': files, 'client_environment': client,
        'package_request': {'roots': {name: libvirt_version for name in PACKAGES}, 'install_recommends': False,
            'forbidden_new_packages': ['libvirt-daemon-system', 'libvirt-daemon-config-network',
                'libvirt-daemon-driver-network', 'libvirt-daemon-driver-nwfilter']},
        'forbidden_vendor_activation': ['libvirtd.service', 'libvirtd.socket', 'libvirtd-ro.socket',
            'libvirtd-admin.socket', 'libvirtd-tcp.socket', 'libvirtd-tls.socket',
            'virtlogd.service', 'virtlogd.socket', 'virtlogd-admin.socket',
            'virtlockd.service', 'virtlockd.socket', 'virtlockd-admin.socket', 'libvirt-guests.service'],
        'service_order': ['dnlab-virtlogd.service', 'dnlab-virtlockd.service', 'dnlab-libvirtd.service'],
        'stop_requirements': ['All dependent VM exits verified before logging/locking stop',
            'No restart, force, package rollback or state removal on uncertain outcomes'],
        'pending': ['Complete dependency transaction and package maintainer/service-hook review',
            'Original account/directory/file ownership and binary/package hashes',
            'No domain autostart and no unqualified pre-existing session state before daemon start',
            'Complete service creation intents before any dependency activation',
            'Native unit/config validation and empty-session operational qualification',
            'Runtime-image socket/PID namespace, KVM, TAP and storage qualification']}
    if layout_version == 2:
        result['driver_layout'] = {'config_base': driver_base, 'qemu_config': driver_base + '/qemu.conf',
                                   'mutable_root': driver_base + '/qemu'}
    if activation_policy is not None:result['activation_policy'] = activation_policy
    return {**result, 'profile_sha256': fingerprint(result)}


def require_installable(profile):
    """Keep v1 readable as history, never install or execute it implicitly."""
    if profile.get('schema_version') != 2 or 'driver_layout' not in profile:
        raise Conflict('session installation requires explicit layout_version=2; historical profile is readonly')


def require_activatable(profile):
    require_installable(profile)
    if profile.get('activation_policy') != EXPLICIT_ACTIVATION:
        raise Conflict('explicit Requisite+After activation profile required; no implicit profile conversion')
