"""Fixture-only durable Docker exec control for an original jumphost.

The observer must qualify container generation and namespace; the result reader
must qualify the original output asset and CLI exit evidence. Neither callback
may execute a new client. Uncertain create/start never causes a second attempt.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import time

from management_service_diagnostics import private_json


class Execution:
    def __init__(self, path, api, owner, config, nonce, observe, read_result, *, readonly=False):
        self.path, self.api = Path(path), api
        self.observe, self.read_result = observe, read_result
        if (not isinstance(owner, dict) or not isinstance(config, dict)
                or not re.fullmatch('[0-9a-f]{64}', str(owner.get('container_id', '')))
                or not re.fullmatch('[0-9a-f]{32}', str(nonce))
                or set(config) != {'User', 'Cmd', 'AttachStdin', 'AttachStdout', 'AttachStderr', 'Tty', 'Privileged'}
                or config.get('User') != 'labuser'
                or any(config.get(k) is not False for k in
                       ('AttachStdin', 'AttachStdout', 'AttachStderr', 'Tty', 'Privileged'))
                or not isinstance(config.get('Cmd'), list) or not config['Cmd']
                or any(not isinstance(arg, str) for arg in config['Cmd'])
                or nonce not in config['Cmd']):
            raise ValueError('qualified CLI exec owner, nonce and detached labuser command required')
        intent = {'owner': deepcopy(owner), 'config': deepcopy(config), 'nonce': nonce}
        if self.path.exists():
            self.record = json.loads(self.path.read_text())
            if any(self.record.get(k) != v for k, v in intent.items()):
                raise RuntimeError('original CLI execution intent differs')
        else:
            if readonly:raise RuntimeError('original CLI execution journal missing; recovery pending')
            self.record = {**intent, 'id': None, 'create_attempted': False,
                           'start_attempted': False, 'exit_verified': False, 'phase': 'intent'}
            self.original()
            self.save()

    def save(self):
        private_json(self.path, self.record)

    def original(self):
        value = self.observe()
        if value.get('owner') != self.record['owner']:
            raise RuntimeError('original jumphost generation differs')
        ids = value.get('exec_ids')
        if (not isinstance(ids, list) or len(ids) != len(set(ids))
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in ids)):
            raise RuntimeError('CLI exec inventory is incomplete')
        identity = self.record['id']
        if identity and set(ids) - {identity}:
            raise RuntimeError('additional jumphost exec requires recovery')
        return ids

    def inspect(self, identity):
        value = self.api.request('GET', '/exec/' + identity + '/json')
        config = self.record['config']
        expected = {'tty': False, 'entrypoint': config['Cmd'][0], 'arguments': config['Cmd'][1:],
                    'privileged': False, 'user': 'labuser'}
        if (value.get('ID') != identity or value.get('ContainerID') != self.record['owner']['container_id']
                or value.get('ProcessConfig') != expected
                or any(value.get(k) is not False for k in ('OpenStdin', 'OpenStdout', 'OpenStderr'))
                or type(value.get('Running')) is not bool or type(value.get('Pid')) is not int
                or value['Pid'] < 0
                or value.get('ExitCode') is not None and type(value['ExitCode']) is not int):
            raise RuntimeError('original CLI exec identity or configuration differs')
        return value

    def prepare(self):
        ids = self.original()
        if self.record['id']:
            self.inspect(self.record['id'])
            return
        if ids:
            if not self.record['create_attempted'] or len(ids) != 1:
                raise RuntimeError('unbound jumphost exec requires recovery')
            identity = ids[0]
            value = self.inspect(identity)
            if value['Running'] or value['ExitCode'] is not None or value['Pid'] != 0:
                raise RuntimeError('unbound CLI exec has already run')
        else:
            if self.record['create_attempted']:
                raise RuntimeError('CLI exec create uncertain; no second create')
            self.record['create_attempted'] = True
            self.save()
            if self.original():
                raise RuntimeError('jumphost exec appeared before allocation')
            result = self.api.request('POST', '/containers/' + self.record['owner']['container_id'] + '/exec',
                                      deepcopy(self.record['config']))
            identity = result.get('Id')
            if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
                raise RuntimeError('CLI exec create reply uncertain')
        self.record.update(id=identity, phase='created')
        self.save()
        self.original()
        self.inspect(identity)

    def run(self, *, timeout=30):
        if type(timeout) not in (int, float) or not 0 < timeout <= 60:
            raise ValueError('bounded CLI exec wait required')
        self.prepare()
        if not self.record['start_attempted']:
            value = self.inspect(self.record['id'])
            if value['Running'] or value['ExitCode'] is not None or value['Pid'] != 0:
                raise RuntimeError('CLI exec ran without original start intent')
            self.record.update(start_attempted=True, phase='starting')
            self.save()
            self.original()
            value = self.inspect(self.record['id'])
            if value['Running'] or value['ExitCode'] is not None or value['Pid'] != 0:
                raise RuntimeError('CLI exec changed before start')
            self.api.request('POST', '/exec/' + self.record['id'] + '/start', {'Detach': True, 'Tty': False})
        deadline = time.monotonic() + timeout
        while True:
            self.original()
            value = self.inspect(self.record['id'])
            if not value['Running']:
                if value['ExitCode'] is None:
                    raise RuntimeError('CLI exec start uncertain; no second start')
                result = self.read_result(deepcopy(self.record), deepcopy(value))
                if (value['ExitCode'] != 0 or not isinstance(result, dict)
                        or result.get('nonce') != self.record['nonce']
                        or result.get('exit_verified') is not True):
                    raise RuntimeError('CLI output or client exit not qualified')
                if self.record.get('result') not in (None, result):
                    raise RuntimeError('original CLI result changed')
                self.record.update(exit_verified=True, phase='completed', result=deepcopy(result), exit_code=0)
                self.save()
                return deepcopy(self.record)
            if time.monotonic() >= deadline:
                raise RuntimeError('CLI exec still running; cleanup pending')
            time.sleep(.05)

    def verify_completed(self):
        if (self.record.get('exit_verified') is not True or self.record.get('phase')!='completed'
                or self.record.get('create_attempted') is not True or self.record.get('start_attempted') is not True
                or type(self.record.get('exit_code')) is not int or self.record['exit_code']!=0
                or not re.fullmatch('[0-9a-f]{64}',str(self.record.get('id','')))):
            raise RuntimeError('CLI execution recovery pending')
        self.original()
        value=self.inspect(self.record['id'])
        if value['Running'] or value['ExitCode']!=0:
            raise RuntimeError('original CLI exec exit differs; recovery pending')
        result=self.read_result(deepcopy(self.record),deepcopy(value))
        if (not isinstance(result,dict) or result.get('nonce')!=self.record['nonce']
                or result.get('exit_verified') is not True or result!=self.record.get('result')):
            raise RuntimeError('original CLI result changed; recovery pending')
        return deepcopy(self.record)
