"""Bounded ICMP/warm-carrier qualification with fixture-owned native peers."""
import json
import time


class DataProbe:
    def __init__(self, slots, management_slot, configure, carrier, attach, detach, ping,
                 path, *, clock=time.monotonic, sleep=time.sleep):
        if not slots or len(set(slots)) != len(slots) or any(type(i) is not int or not 0 <= i <= 15 or i == management_slot for i in slots):
            raise ValueError('data probe slots must be unique data ports outside management')
        self.slots = list(slots)
        self.configure, self.carrier, self.attach, self.detach, self.ping = configure, carrier, attach, detach, ping
        self.path, self.clock, self.sleep = path, clock, sleep
        self.events, self.attached = [], set()

    def record(self, event):
        self.events.append(event)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.write_text(json.dumps(self.events, indent=2) + '\n')
        self.path.chmod(0o600)

    def traffic(self, slot, expected, stage):
        deadline = self.clock() + (30 if expected else 8)
        consecutive = 0
        while True:
            result = self.ping(slot)
            reachable = result.returncode == 0
            self.record({'stage': stage, 'slot': slot, 'expected_reachable': expected,
                         'returncode': result.returncode, 'output': result.stdout + result.stderr})
            consecutive = consecutive + 1 if reachable == expected else 0
            if consecutive >= (1 if expected else 2):
                return
            if self.clock() >= deadline:
                raise RuntimeError(f'data slot {slot} traffic differs from carrier state at {stage}')
            self.sleep(.2)

    def prepare(self):
        for slot in self.slots:
            self.attach(slot)
            self.attached.add(slot)
            self.configure(slot)
            self.record({'stage': 'initial-down', 'slot': slot, 'action': 'carrier', 'state': 'down'})
            self.carrier(slot, 'down')
            self.traffic(slot, False, 'initial-down')
            self.record({'stage': 'first-up', 'slot': slot, 'action': 'carrier', 'state': 'up'})
            self.carrier(slot, 'up')
            self.traffic(slot, True, 'first-up')
            self.record({'stage': 'cycle-down', 'slot': slot, 'action': 'carrier', 'state': 'down'})
            self.carrier(slot, 'down')
            self.traffic(slot, False, 'cycle-down')
            # Carrier goes down before detaching the fixture's peer address.
            self.detach(slot)
            self.attached.remove(slot)
            self.attach(slot)
            self.attached.add(slot)
            self.record({'stage': 'reattached-up', 'slot': slot, 'action': 'carrier', 'state': 'up'})
            self.carrier(slot, 'up')
            self.traffic(slot, True, 'reattached-up')
        self.record({'stage': 'prepared', 'slots': self.slots})

    def verify(self, stage):
        for slot in self.slots:
            self.traffic(slot, True, stage)
        self.record({'stage': stage + '-verified', 'slots': self.slots})

    def finish(self):
        for slot in self.slots:
            if slot in self.attached:
                self.record({'stage': 'final-down', 'slot': slot, 'action': 'carrier', 'state': 'down'})
                self.carrier(slot, 'down')
                self.traffic(slot, False, 'final-down')
                self.detach(slot)
                self.attached.remove(slot)
        self.record({'stage': 'finished', 'slots': self.slots})
