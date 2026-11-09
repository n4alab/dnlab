"""Read-only observation of an original persistent libvirt VM generation.

The reference must come from the durable qualified creation acknowledgement,
not from discovery of a currently matching domain. No connection is opened and
no process is discovered here. A host pidfd/process provider is mandatory; the
libvirt domain ID is never treated as a QEMU PID.
"""
from copy import deepcopy
from xml.etree import ElementTree as ET

from .libvirt_xml import OWNER_NS
from .manifest import Conflict, fingerprint
from .vm_events import validate_birth, validate_observation
from .vm_template import digest, fields, require


def xml_fingerprint(xml, birth):
    require(isinstance(xml, str) and 0 < len(xml.encode()) <= 1024 * 1024
            and '<!DOCTYPE' not in xml.upper() and '<!ENTITY' not in xml.upper(), 'bounded domain XML without DTD required')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise Conflict('invalid libvirt domain XML') from error
    require(root.tag == 'domain' and root.get('type') == 'kvm'
            and len(root.findall('uuid')) == 1 and root.findtext('uuid') == birth['uuid'], 'domain XML UUID or backend differs')
    owners = root.findall('metadata/{' + OWNER_NS + '}owner')
    require(len(root.findall('metadata')) == 1 and len(owners) == 1, 'unique original domain owner required')
    owner = owners[0].attrib
    expected = {key: str(value) for key, value in birth.items() if key != 'uuid'}
    require(set(owner) == set(expected) | {'management_port'}
            and all(owner[key] == value for key, value in expected.items()) and owner['management_port'],
            'domain XML original birth differs')
    def describe(element):
        text = element.text if element.text and element.text.strip() else None
        tail = element.tail if element.tail and element.tail.strip() else None
        return [element.tag, dict(element.attrib), text, tail, [describe(child) for child in element]]
    return fingerprint(describe(root))


def creation_reference(birth, *, uri, persistent_xml, live_xml, process):
    """Serialize supplied creation proofs; never acquire or adopt a domain."""
    validate_birth(birth)
    persistent = xml_fingerprint(persistent_xml, birth)
    live = xml_fingerprint(live_xml, birth)
    validate_observation({'birth': birth, 'config_sha256': fingerprint([persistent, live]), 'process': process}, birth)
    require(process is not None and isinstance(uri, str) and uri, 'original running creation acknowledgement required')
    return {'birth': deepcopy(birth), 'uri': uri, 'persistent_sha256': persistent,
            'live_sha256': live, 'process_sha256': fingerprint(process)}


class LibvirtDomainObserver:
    def __init__(self, connection, reference, *, xml_inactive_flag, process):
        fields(reference, ('birth', 'uri', 'persistent_sha256', 'live_sha256', 'process_sha256'), 'domain creation reference')
        validate_birth(reference['birth'])
        require(isinstance(reference['uri'], str) and reference['uri']
                and all(digest(reference[key]) for key in ('persistent_sha256', 'live_sha256', 'process_sha256'))
                and type(xml_inactive_flag) is int and xml_inactive_flag == 2
                and callable(getattr(process, 'capture', None)), 'pinned domain reference and process provider required')
        self.connection, self.reference = connection, deepcopy(reference)
        self.flag, self.process = xml_inactive_flag, process

    def _configuration(self):
        reference = self.reference; birth = reference['birth']
        if self.connection.getURI() != reference['uri']:raise Conflict('original hypervisor URI differs')
        domain = self.connection.lookupByUUIDString(birth['uuid'])
        if domain.UUIDString() != birth['uuid'] or domain.isActive() != 1:
            raise Conflict('original running domain unavailable')
        persistent = xml_fingerprint(domain.XMLDesc(self.flag), birth)
        live = xml_fingerprint(domain.XMLDesc(0), birth)
        if persistent != reference['persistent_sha256'] or live != reference['live_sha256']:
            raise Conflict('original persistent or live VM configuration changed')
        if domain.UUIDString() != birth['uuid'] or domain.isActive() != 1 or self.connection.getURI() != reference['uri']:
            raise Conflict('domain or hypervisor changed during observation')
        return fingerprint([persistent, live])

    def __call__(self, birth):
        if birth != self.reference['birth']:raise Conflict('domain observer original birth differs')
        first = self._configuration()
        with self.process.capture(deepcopy(birth)) as proof:
            result = {'birth': deepcopy(birth), 'config_sha256': first, 'process': deepcopy(proof)}
            validate_observation(result, birth)
            if proof is None or fingerprint(proof) != self.reference['process_sha256']:
                raise Conflict('original QEMU process incarnation changed')
            if self._configuration() != first:raise Conflict('VM changed during process observation')
            return result
