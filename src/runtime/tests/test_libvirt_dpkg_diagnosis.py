"""Only synthetic bytes; no actual dpkg database, host or service access."""
import hashlib

import pytest

from tools.libvirt_dpkg_diagnosis import diagnose, records


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def status(name='libvirt0', arch='amd64', version='11.3', extra=''):
    return (f'Package: {name}\nArchitecture: {arch}\nVersion: {version}\n'
            f'Status: install ok installed\n{extra}\n').encode()


BASE = status(extra='Description: synthetic\n continuation\n')
FACTS = {name: {key: row[key] for key in ('Package', 'Architecture', 'Version', 'Status')}
         for (name, _), row in records(BASE)[0].items()}


def compare(current, baseline=BASE, *, expected=digest(BASE)):
    return diagnose(expected_sha256=expected, observed_sha256=digest(current),
                    observed_raw=current, baseline_raw=baseline, expected_packages=FACTS)


def test_missing_baseline_keeps_unknown_cause_even_when_all_selected_facts_match():
    report = compare(BASE + status('unrelated'), baseline=None)
    assert report['comparison'] == 'baseline-bytes-missing'
    assert report['qualified'] is False and report['global_matches'] is False
    assert all(row['matches'] for row in report['selected_packages'])
    assert report['changes'] is None and report['record_order_changed'] is None


def test_identical_bytes_remain_diagnostic_not_qualification():
    report = compare(BASE)
    assert report['global_matches'] and report['changes'] == []
    assert report['qualified'] is False


def test_all_records_compared_including_packages_outside_selected_projection():
    old = BASE + status('gone') + status('changed', extra='Auto-Installed: yes\n')
    new = BASE + status('added') + status('changed', extra='Auto-Installed: no\n')
    report = compare(new, old, expected=digest(old))
    assert [(row['package'], row['change']) for row in report['changes']] == [
        ('added', 'added'), ('changed', 'modified'), ('gone', 'removed')]
    assert report['changes'][1]['fields'][0]['field'] == 'Auto-Installed'
    assert all(row['matches'] for row in report['selected_packages'])


def test_version_and_status_changes_are_not_hidden():
    new = status(version='12').replace(b'install ok installed', b'deinstall ok config-files')
    report = compare(new)
    assert report['selected_packages'][0]['matches'] is False
    assert {'Version', 'Status'} <= {field['field'] for field in report['changes'][0]['fields']}


def test_continuation_change_is_reported_without_dumping_field_content():
    report = compare(BASE.replace(b' continuation', b' different'))
    fields = report['changes'][0]['fields']
    assert len(fields) == 1 and fields[0]['field'] == 'Description'
    assert fields[0]['expected'] != fields[0]['observed']
    assert 'synthetic' not in str(fields)


def test_serialization_order_preserves_global_delta():
    old = BASE + status('another')
    new = status('another') + BASE
    report = compare(new, old, expected=digest(old))
    assert report['changes'] == [] and report['record_order_changed'] is True
    assert report['global_matches'] is False and report['qualified'] is False
    reordered_fields = BASE.replace(b'Package: libvirt0\nArchitecture: amd64',
                                    b'Architecture: amd64\nPackage: libvirt0')
    report = compare(reordered_fields)
    assert report['changes'] == [] and report['global_matches'] is False


@pytest.mark.parametrize('which', ['baseline', 'observed'])
def test_raw_artifacts_must_match_explicit_digests(which):
    with pytest.raises(ValueError, match='artifact digest differs'):
        diagnose(expected_sha256='a' * 64 if which == 'baseline' else digest(BASE),
                 observed_sha256='b' * 64 if which == 'observed' else digest(BASE),
                 observed_raw=BASE, baseline_raw=BASE, expected_packages=FACTS)


@pytest.mark.parametrize('raw', [b'', b' stray\n', b'not-a-field\n',
    BASE + BASE, BASE.replace(b'Version: 11.3', b'Version: 11.3\nversion: 12'),
    BASE.replace(b'Package:', b'package:'), BASE.replace(b'\n', b'\r\n'),
    BASE + b'\x00', b'Package: missing-arch\n', b'\xff'])
def test_ambiguous_or_unsupported_status_is_not_silently_normalized(raw):
    with pytest.raises((ValueError, UnicodeError)):
        records(raw)


def test_multiarch_records_are_distinct_but_legacy_selected_projection_refuses_ambiguity():
    raw = BASE + status(arch='arm64')
    assert len(records(raw)[0]) == 2
    with pytest.raises(ValueError, match='multiarch ambiguous'):
        compare(raw)


def test_missing_selected_package_is_reported():
    report = compare(status('another'))
    assert report['selected_packages'][0]['observed'] is None
    assert report['selected_packages'][0]['matches'] is False


def test_diagnosis_uses_only_supplied_bytes(monkeypatch):
    import builtins
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        pytest.fail('unexpected filesystem or command access')

    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(os, 'open', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    assert compare(BASE)['changes'] == []
