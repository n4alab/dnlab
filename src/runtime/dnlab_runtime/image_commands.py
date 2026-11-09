"""Explicit execution contract for experimental candidate images."""

from .manifest import Conflict


PYTHON_LABEL = 'org.dnlab.runtime-management.python'
PYTHON_COMMANDS = {
    'system': ('python3',),
    'uv': ('uv', 'run', '--offline', 'python3'),
}


def python_command(image, program):
    config = image.get('Config') or {}
    profile = (config.get('Labels') or {}).get(PYTHON_LABEL)
    if not isinstance(profile, str) or profile not in PYTHON_COMMANDS:
        raise Conflict('candidate requires an explicit supported Python profile')
    return [*PYTHON_COMMANDS[profile], '-c', program]


def healthcheck_command(image):
    # Only exec-form checks are qualified. No shell or inferred interpreter.
    test = ((image.get('Config') or {}).get('Healthcheck') or {}).get('Test')
    if not isinstance(test, list) or len(test) < 2 or test[0] != 'CMD' or not all(isinstance(arg, str) and arg and '\x00' not in arg for arg in test):
        raise Conflict('candidate requires an exec-form image healthcheck')
    return test[1:]
