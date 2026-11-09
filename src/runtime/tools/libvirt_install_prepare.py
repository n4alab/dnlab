"""Prepare-only assembly from saved evidence and explicit host providers.

There is deliberately no host CLI or account execution transport in this module.
The operational recipe must qualify its input files and obtain authorization
before calling it. Preparation writes only its caller-owned journal.
"""
from copy import deepcopy
from pathlib import PurePosixPath
import stat

from dnlab_runtime.libvirt_install_session import SessionProvisioning
from dnlab_runtime.libvirt_service_profile import render_profile, require_installable
from dnlab_runtime.manifest import Conflict, fingerprint


class PreparationOnlyRunner:
    def _refuse(self, *args, **kwargs):
        raise Conflict('prepare-only entry cannot execute or recover account workers')
    arm = verify = release = outcome = _refuse


def directory_receipts(profile, snapshot, inventory, selected_paths):
    """Translate only explicitly selected, already observed directory identities."""
    if (not isinstance(snapshot, dict) or set(snapshot) != {'context', 'prerequisites'}
            or snapshot['prerequisites'].get('profile_sha256') != profile['profile_sha256']
            or inventory.get('status') != 'collected'
            or inventory.get('profile_sha256') != profile['profile_sha256']
            or inventory.get('observation_sha256') != fingerprint(inventory.get('observed'))
            or inventory.get('blocking_findings') != []
            or inventory.get('account_conflicts') != [] or inventory.get('group_conflicts') != []
            or not isinstance(selected_paths, list) or len(set(selected_paths)) != len(selected_paths)
            or set(inventory.get('occupied_targets', [])) != set(selected_paths)):
        raise Conflict('original complete installation inventory and explicit dependencies required')
    directories = {item['path']:item for item in profile['directories']}
    parents = snapshot['prerequisites'].get('os_parents', {})
    result = {}
    for path in selected_paths:
        spec = directories.get(path)
        value = inventory['observed']['paths'].get(path, {})
        info = value.get('metadata')
        if (spec is None or (spec['uid'], spec['gid'], spec['mode']) != (0, 0, 0o755)
                or value.get('status') != 'present' or value.get('kind') != 'directory'
                or not isinstance(info, list) or len(info) != 8
                or any(type(n) is not int for n in info)
                or not stat.S_ISDIR(info[2]) or (info[3], info[4], stat.S_IMODE(info[2])) != (0, 0, 0o755)):
            raise Conflict('original root-controlled directory dependency differs')
        ancestors = {}
        for parent in PurePosixPath(path).parents:
            item = parents.get(str(parent))
            if (not isinstance(item, dict) or set(item) != {'device', 'inode', 'uid', 'gid', 'mode'}
                    or any(type(n) is not int for n in item.values())
                    or (item['uid'], item['gid'], item['mode']) != (0, 0, 0o755)):
                raise Conflict('original directory ancestor proof missing or differs')
            ancestors[str(parent)] = dict(item, kind='directory')
        result[path] = dict(dependency='existing_directory', path=path,
            identity=dict(device=info[0], inode=info[1], uid=info[3], gid=info[4],
                          mode=stat.S_IMODE(info[2]), kind='directory'), ancestors=ancestors)
    return result


def prepare_only(journal, *, root, request, baseline, snapshot_provider,
                 window, nss_query, dependency_paths):
    profile = render_profile(**request)
    require_installable(profile)
    if not isinstance(baseline, dict) or baseline.get('status') != 'collected':
        raise Conflict('original successful collection required')
    original = deepcopy(baseline['snapshot'])
    dependencies = directory_receipts(profile, original, baseline['targets'], dependency_paths)
    session = SessionProvisioning(journal, root=root, request=request, snapshot_provider=snapshot_provider,
        original_snapshot=original, window=window, runner=PreparationOnlyRunner(),
        nss_query=nss_query, directory_receipts=dependencies)
    return session.prepare()
