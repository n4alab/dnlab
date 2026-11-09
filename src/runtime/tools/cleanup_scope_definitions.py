"""Exact scope definitions bound to reviewed Docker configuration profiles.

Profiles are trusted, authenticated local qualification data, not input learned
from a gate request or a running container. This component performs no IO and
does not authenticate a Docker birth, journal or current process by itself.
"""
from copy import deepcopy
import hashlib
import stat

from cleanup_execution import canonical_digest, require, sha
from cleanup_scope_sources import ROOT, indexed

CONFIG_FIELDS = ('Privileged', 'Devices', 'DeviceCgroupRules', 'CgroupParent',
                 'CgroupnsMode', 'CapAdd', 'CapDrop')
TOKEN = '${container_id}'
FILES = ('', '.d/50-DeviceAllow.conf', '.d/50-DevicePolicy.conf')


def configuration(inspect):
    host = inspect.get('HostConfig') if type(inspect) is dict else None
    require(type(host) is dict and all(key in host for key in CONFIG_FIELDS),
            'complete observed Docker scope configuration required')
    require(type(host['Privileged']) is bool, 'explicit Docker privilege mode required')
    return {key: deepcopy(host[key]) for key in CONFIG_FIELDS}


class ScopeDefinitions:
    """Verify exact scoped files for one of a finite set of qualified configs.

    A separate current-state provider must bind the entire Docker config and
    generation to its original birth and journal; this selection is deliberately
    only the scope-definition profile, not general container ownership proof.
    """

    def __init__(self, profiles):
        require(type(profiles) is list and profiles, 'reviewed scope profiles required')
        self._profiles = {}
        for profile in profiles:
            require(type(profile) is dict and set(profile) == {'configuration', 'files', 'directory'},
                    'complete reviewed scope profile required')
            selected = configuration({'HostConfig': profile['configuration']})
            require(set(profile['configuration']) == set(CONFIG_FIELDS), 'exact scope config selector required')
            key = canonical_digest(selected)
            require(key not in self._profiles and type(profile['files']) is dict
                    and set(profile['files']) == set(FILES), 'distinct scope configs and exact file set required')
            for suffix, row in profile['files'].items():
                require(type(row) is dict and set(row) == {'template', 'mode', 'uid', 'gid'}
                        and type(row['template']) is str and len(row['template'].encode()) <= 65536
                        and row['template'].count(TOKEN) == (1 if suffix == '' else 0),
                        'bounded exact definition template required')
                self._permissions(row)
            self._permissions(profile['directory'])
            require(set(profile['directory']) == {'mode', 'uid', 'gid'}, 'exact directory profile required')
            self._profiles[key] = deepcopy(profile)
        self.sha256 = canonical_digest(profiles)

    @staticmethod
    def _permissions(value):
        require(type(value) is dict and {'mode', 'uid', 'gid'} <= set(value)
                and type(value['mode']) is int and value['mode'] in (0o644, 0o755)
                and type(value['uid']) is int and value['uid'] == 0
                and type(value['gid']) is int and value['gid'] == 0,
                'qualified root-owned scope permissions required')

    def verify(self, container_id, inspect, rows, bodies):
        require(sha(container_id) and inspect.get('Id') == container_id,
                'original Docker scope identity required')
        key = canonical_digest(configuration(inspect))
        require(key in self._profiles, 'Docker scope configuration not qualified')
        profile = self._profiles[key]
        scope = ROOT + '/docker-' + container_id + '.scope'
        current = indexed({'complete': True, 'candidates': rows})
        paths = {scope + suffix for suffix in FILES}
        require(set(current) == paths | {scope + '.d'} and type(bodies) is dict
                and set(bodies) == paths, 'exact current scope and drop-in inventory required')
        for path, row in current.items():
            directory = path == scope + '.d'
            metadata = row.get('metadata')
            require(type(metadata) is list and len(metadata) == 8
                    and all(type(value) is int and value >= 0 for value in metadata),
                    'current scope file identity required')
            expected = profile['directory'] if directory else profile['files'][path[len(scope):]]
            kind = stat.S_IFDIR if directory else stat.S_IFREG
            require(row.get('kind') == ('directory' if directory else 'file')
                    and stat.S_IFMT(metadata[2]) == kind
                    and [stat.S_IMODE(metadata[2]), metadata[3], metadata[4]]
                    == [expected['mode'], expected['uid'], expected['gid']],
                    'scope type or ownership differs from qualification')
            if directory:
                require(row.get('names') == ['50-DeviceAllow.conf', '50-DevicePolicy.conf'],
                        'scope drop-in names differ')
                continue
            raw = bodies[path]
            require(type(raw) is bytes and raw == expected['template'].replace(TOKEN, container_id).encode()
                    and metadata[5] == len(raw) and hashlib.sha256(raw).hexdigest() == row.get('sha256'),
                    'scope definition differs from qualified Docker profile')
        return {'container_id': container_id, 'definition_profile_sha256': self.sha256,
                'rows_sha256': canonical_digest(rows)}
