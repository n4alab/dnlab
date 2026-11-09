import pytest

from dnlab_runtime.image_commands import healthcheck_command, python_command
from dnlab_runtime.manifest import Conflict


@pytest.mark.parametrize('profile,expected', [
    ('system', ['python3', '-c', 'program']),
    ('uv', ['uv', 'run', '--offline', 'python3', '-c', 'program']),
])
def test_python_uses_explicit_image_profile(profile, expected):
    image = {'Config': {'Labels': {'org.dnlab.runtime-management.python': profile}}}
    assert python_command(image, 'program') == expected


@pytest.mark.parametrize('test', [
    ['CMD', '/healthcheck.py'], ['CMD', 'uv', 'run', '/healthcheck.py'],
])
def test_healthcheck_preserves_image_exec_command(test):
    assert healthcheck_command({'Config': {'Healthcheck': {'Test': test}}}) == test[1:]


@pytest.mark.parametrize('test', [None, [], ['NONE'], ['CMD'], ['CMD-SHELL', 'python3 /healthcheck.py'], ['CMD', ''], ['CMD', 1], ['CMD', 'bad\x00command']])
def test_incomplete_or_shell_healthcheck_is_rejected(test):
    with pytest.raises(Conflict):
        healthcheck_command({'Config': {'Healthcheck': {'Test': test}}})
