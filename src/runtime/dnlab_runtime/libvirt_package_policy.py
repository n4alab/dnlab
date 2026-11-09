"""Selected installed-package checks; Debian resolves declared dependencies.

The global dpkg database digest is diagnostic for this explicit policy. It is
not a compatibility proof or a reason to requalify after unrelated apt changes.
Other resource, binary and configuration identity guards remain independent.
"""
from copy import deepcopy

from .manifest import Conflict


INSTALLED_PACKAGES = 'installed-packages-v1'


def prerequisites_for_policy(value, policy):
    if policy not in (None, INSTALLED_PACKAGES):
        raise Conflict('unsupported installed package policy')
    result = deepcopy(value)
    if policy is None:
        return result
    packages = result.get('packages')
    if not isinstance(packages, dict) or not packages:
        raise Conflict('explicit installed package inventory required')
    for name, row in packages.items():
        if (not isinstance(name, str) or not name or not isinstance(row, dict)
                or set(row) != {'Package', 'Version', 'Architecture', 'Status'}
                or row['Package'] != name or row['Status'] != 'install ok installed'
                or any(not isinstance(field, str) or not field for field in row.values())):
            raise Conflict('complete installed package facts required')
    result.pop('dpkg_status_sha256', None)
    return result
