"""Offline dpkg status comparison, supplied bytes only; never qualifies a host.

No filesystem, subprocess, NSS, package manager or service access. A historical
digest is not a historical database: without authenticated baseline bytes the
cause of a global delta remains unknown, even if selected package facts match.
"""
import hashlib
import re


LIMIT = 32 * 1024 * 1024
CORE = ('Package', 'Architecture', 'Version', 'Status')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('explicit lowercase SHA256 required')
    return value


def records(raw):
    """Strict diagnostic Deb822 subset; preserve continuation bytes as text.

    Unsupported or ambiguous input fails instead of silently dropping fields.
    No dependency resolution or installed-package qualification is attempted.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > LIMIT:
        raise ValueError('nonempty bounded status bytes required')
    text = raw.decode('utf-8')
    if '\x00' in text or '\r' in text:
        raise ValueError('unsupported status control character')
    result = {}; order = []; fields = {}; previous = None

    def finish():
        if not fields:
            return
        name, arch = fields.get('Package', ''), fields.get('Architecture', '')
        if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', arch)):
            raise ValueError('unambiguous package and architecture required')
        identity = (name, arch)
        if identity in result:
            raise ValueError('duplicate package architecture identity')
        result[identity] = dict(fields); order.append(identity)

    for line in text.split('\n'):
        if line == '':
            finish(); fields = {}; previous = None
        elif line[0] in ' \t':
            if previous is None:
                raise ValueError('orphan continuation')
            fields[previous] += '\n' + line
        else:
            key, separator, value = line.partition(':')
            if not separator or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', key):
                raise ValueError('malformed status field')
            folded = key.lower()
            if any(existing.lower() == folded for existing in fields):
                raise ValueError('duplicate status field')
            # Identity fields must use their canonical spelling. Other fields
            # remain exact, including leading spaces and continuation lines.
            if folded in {item.lower() for item in CORE} and key not in CORE:
                raise ValueError('noncanonical identity field')
            fields[key] = value[1:] if value.startswith(' ') else value
            previous = key
    finish()
    return result, order


def _field(value):
    return None if value is None else dict(sha256=_sha(value.encode('utf-8')),
                                         bytes=len(value.encode('utf-8')))


def diagnose(*, expected_sha256, observed_sha256, observed_raw,
             expected_packages, baseline_raw=None):
    """Compare authenticated supplied artifacts; never changes acceptance rules.

    expected_packages is the original name-keyed four-field projection, not a
    dependency closure. A selected package with multiple architectures is
    explicitly ambiguous for that legacy projection.
    """
    _digest(expected_sha256); _digest(observed_sha256)
    current, current_order = records(observed_raw)
    if _sha(observed_raw) != observed_sha256:
        raise ValueError('observed artifact digest differs')
    if not isinstance(expected_packages, dict) or not expected_packages:
        raise ValueError('original selected package facts required')
    selected = []
    for name, expected in sorted(expected_packages.items()):
        if (not isinstance(expected, dict) or set(expected) != set(CORE)
                or expected['Package'] != name
                or any(not isinstance(value, str) or not value for value in expected.values())):
            raise ValueError('original four-field package facts required')
        candidates = [row for (package, _), row in current.items() if package == name]
        if len(candidates) > 1:
            raise ValueError('selected package projection is multiarch ambiguous')
        observed = {key: candidates[0].get(key) for key in CORE} if candidates else None
        selected.append(dict(package=name, expected=dict(expected), observed=observed,
                             matches=expected == observed))
    report = dict(kind='offline-dpkg-diagnosis-v1', qualified=False,
        expected_sha256=expected_sha256, observed_sha256=observed_sha256,
        global_matches=expected_sha256 == observed_sha256,
        selected_packages=selected, observed_records=len(current),
        baseline_available=baseline_raw is not None,
        changes=None, record_order_changed=None,
        limitations=['Diagnostic only; original prerequisite guard remains unchanged',
                     'Selected facts do not establish dependency closure or compatibility',
                     'No attribution to an actor, time or package operation'])
    if baseline_raw is None:
        report['comparison'] = 'baseline-bytes-missing'
        return report
    original, original_order = records(baseline_raw)
    if _sha(baseline_raw) != expected_sha256:
        raise ValueError('baseline artifact digest differs')
    changes = []
    for identity in sorted(original.keys() | current.keys()):
        before, after = original.get(identity), current.get(identity)
        if before == after:
            continue
        fields = [dict(field=key, expected=_field((before or {}).get(key)),
                       observed=_field((after or {}).get(key)))
                  for key in sorted((before or {}).keys() | (after or {}).keys())
                  if (before or {}).get(key) != (after or {}).get(key)]
        changes.append(dict(package=identity[0], architecture=identity[1],
            change='added' if before is None else 'removed' if after is None else 'modified',
            fields=fields))
    report.update(comparison='authenticated-records-compared', changes=changes,
                  baseline_records=len(original), record_order_changed=original_order != current_order)
    return report
