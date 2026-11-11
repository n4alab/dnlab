"""Retire unused monitor metadata while preserving the completed reload."""

import json

from .manifest import Conflict, canonical, fingerprint


def retire_unused_monitors(controller, reference):
    journal = controller.journal
    with journal.execution_lock, journal.transaction():
        value = controller._reference(reference)
        reload = value['items'][0]
        if reload['spec']['kind'] != 'reload' or reload['phase'] not in ('requested', 'confirmed'):
            raise Conflict('original completed reload required before monitor recovery')
        if controller.commands.original_completion(reload, value['id']) is None:
            raise Conflict('original reload exit evidence missing')
        for item in value['items'][1:]:
            command = controller.command_builder(controller.source, item, value['id'], controller.binary)
            if (item['phase'] != 'prepared' or controller.commands.inspect_intent(item, value['id']) is not None
                    or journal.db.execute('SELECT 1 FROM libvirt_activation_acknowledgements WHERE activation_id=? AND nonce=?',
                                          (value['id'], item['nonce'])).fetchone()
                    or journal.db.execute('SELECT 1 FROM libvirt_activation_start_jobs WHERE request_sha256=?',
                                          (command['request_sha256'],)).fetchone()):
                raise Conflict('service start already tracked; original monitor cannot be replaced')
            controller._window(item)
        binding = journal.db.execute('SELECT * FROM libvirt_activation_monitor_bindings WHERE activation_id=?',
                                     (value['id'],)).fetchone()
        rows = journal.db.execute('SELECT * FROM libvirt_activation_event_monitors WHERE activation_id=?',
                                  (value['id'],)).fetchall()
        if binding is None or len(rows) != 3:
            raise Conflict('complete unused original monitor inventory required')
        saved = json.loads(binding['payload'])
        if (fingerprint(saved) != binding['fingerprint'] or saved['activation_id'] != value['id']
                or saved['installation_sha256'] != fingerprint(controller.source)
                or saved['window_sha256'] != controller.window.sha256 or set(saved['references']) != {
                item['spec']['unit'] for item in value['items'][1:]}):
            raise Conflict('original unused monitor binding differs')
        records = []
        for row in rows:
            record = json.loads(row['payload'])
            matches = [item for item in value['items'][1:] if item['nonce'] == row['nonce']]
            if (len(matches) != 1 or fingerprint(record) != row['fingerprint']
                    or record['request'] != controller.monitor_request(value, matches[0])
                    or record['reference'] != saved['references'][matches[0]['spec']['unit']]
                    or record['cursor'] != record['subscription']['barrier']
                    or any(record[key] is not None for key in ('job', 'invocation', 'proof'))
                    or record['completed'] or record['phase'] != 'tracking'):
                raise Conflict('original monitor contains observed service activity')
            records.append(record)
        controller.observe(value)
        archive = dict(binding=saved, monitors=records, reload=controller.commands.original_completion(reload, value['id']))
        journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_activation_retired_monitors '
                           '(sha256 TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        journal.db.execute('INSERT INTO libvirt_activation_retired_monitors VALUES(?,?)',
                           (fingerprint(archive), canonical(archive)))
        journal.db.execute('DELETE FROM libvirt_activation_event_monitors WHERE activation_id=?', (value['id'],))
        journal.db.execute('DELETE FROM libvirt_activation_monitor_bindings WHERE activation_id=?', (value['id'],))
