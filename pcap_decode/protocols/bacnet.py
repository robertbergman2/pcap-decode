import struct
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional, Tuple

from pcap_decode.models import Packet

BVLC_TYPE_BACNET_IP = 0x81

BVLC_FUNCTIONS = {
    0x00: "bvlc-result",
    0x01: "write-broadcast-distribution-table",
    0x02: "read-broadcast-distribution-table",
    0x03: "read-broadcast-distribution-table-ack",
    0x04: "forwarded-npdu",
    0x05: "register-foreign-device",
    0x06: "read-foreign-device-table",
    0x07: "read-foreign-device-table-ack",
    0x08: "delete-foreign-device-table-entry",
    0x09: "distribute-broadcast-to-network",
    0x0A: "original-unicast-npdu",
    0x0B: "original-broadcast-npdu",
    0x0C: "secure-bvll",
}

# BVLC functions that wrap an NPDU, mapped to the extra header bytes sitting between the
# BVLC header and the NPDU. forwarded-npdu prefixes the originating device's B/IP address.
NPDU_BEARING_FUNCTIONS = {0x04: 6, 0x09: 0, 0x0A: 0, 0x0B: 0}

APDU_CONFIRMED_REQUEST = 0x0
APDU_UNCONFIRMED_REQUEST = 0x1
APDU_SIMPLE_ACK = 0x2
APDU_COMPLEX_ACK = 0x3
APDU_SEGMENT_ACK = 0x4
APDU_ERROR = 0x5
APDU_REJECT = 0x6
APDU_ABORT = 0x7

APDU_TYPES = {
    APDU_CONFIRMED_REQUEST: "confirmed-request",
    APDU_UNCONFIRMED_REQUEST: "unconfirmed-request",
    APDU_SIMPLE_ACK: "simple-ack",
    APDU_COMPLEX_ACK: "complex-ack",
    APDU_SEGMENT_ACK: "segment-ack",
    APDU_ERROR: "error",
    APDU_REJECT: "reject",
    APDU_ABORT: "abort",
}

SERVICE_ATOMIC_READ_FILE = 6
SERVICE_ATOMIC_WRITE_FILE = 7

CONFIRMED_SERVICES = {
    0: "acknowledgeAlarm",
    1: "confirmedCOVNotification",
    2: "confirmedEventNotification",
    3: "getAlarmSummary",
    4: "getEnrollmentSummary",
    5: "subscribeCOV",
    6: "atomicReadFile",
    7: "atomicWriteFile",
    8: "addListElement",
    9: "removeListElement",
    10: "createObject",
    11: "deleteObject",
    12: "readProperty",
    13: "readPropertyConditional",
    14: "readPropertyMultiple",
    15: "writeProperty",
    16: "writePropertyMultiple",
    17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer",
    19: "confirmedTextMessage",
    20: "reinitializeDevice",
    21: "vtOpen",
    22: "vtClose",
    23: "vtData",
    24: "authenticate",
    25: "requestKey",
    26: "readRange",
    27: "lifeSafetyOperation",
    28: "subscribeCOVProperty",
    29: "getEventInformation",
}

UNCONFIRMED_SERVICES = {
    0: "i-Am",
    1: "i-Have",
    2: "unconfirmedCOVNotification",
    3: "unconfirmedEventNotification",
    4: "unconfirmedPrivateTransfer",
    5: "unconfirmedTextMessage",
    6: "timeSynchronization",
    7: "who-Has",
    8: "who-Is",
    9: "utcTimeSynchronization",
    10: "writeGroup",
}

NETWORK_MESSAGE_TYPES = {
    0x00: "Who-Is-Router-To-Network",
    0x01: "I-Am-Router-To-Network",
    0x02: "I-Could-Be-Router-To-Network",
    0x03: "Reject-Message-To-Network",
    0x04: "Router-Busy-To-Network",
    0x05: "Router-Available-To-Network",
    0x06: "Initialize-Routing-Table",
    0x07: "Initialize-Routing-Table-Ack",
    0x08: "Establish-Connection-To-Network",
    0x09: "Disconnect-Connection-To-Network",
    0x0A: "Challenge-Request",
    0x0B: "Security-Payload",
    0x0C: "Security-Response",
    0x0D: "Request-Key-Update",
    0x0E: "Update-Key-Set",
    0x0F: "Update-Distribution-Key",
    0x10: "Request-Master-Key",
    0x11: "Set-Master-Key",
    0x12: "What-Is-Network-Number",
    0x13: "Network-Number-Is",
}

ERROR_CLASSES = {
    0: "device",
    1: "object",
    2: "property",
    3: "resources",
    4: "security",
    5: "services",
    6: "vt",
    7: "communication",
}

REJECT_REASONS = {
    0: "other",
    1: "buffer-overflow",
    2: "inconsistent-parameters",
    3: "invalid-parameter-data-type",
    4: "invalid-tag",
    5: "missing-required-parameter",
    6: "parameter-out-of-range",
    7: "too-many-arguments",
    8: "undefined-enumeration",
    9: "unrecognized-service",
}

ABORT_REASONS = {
    0: "other",
    1: "buffer-overflow",
    2: "invalid-apdu-in-this-state",
    3: "preempted-by-higher-priority-task",
    4: "segmentation-not-supported",
    5: "security-error",
    6: "insufficient-security",
    7: "window-size-out-of-range",
    8: "application-exceeded-reply-time",
    9: "out-of-resources",
    10: "tsm-timeout",
    11: "apdu-too-long",
}

# A peer refusing a service it does not implement, or rejecting the encoding, is what
# protocol probing looks like from the responder's side.
PROBING_REJECT_REASONS = frozenset({4, 8, 9})

OBJECT_TYPES = {
    0: "analog-input",
    1: "analog-output",
    2: "analog-value",
    3: "binary-input",
    4: "binary-output",
    5: "binary-value",
    6: "calendar",
    7: "command",
    8: "device",
    9: "event-enrollment",
    10: "file",
    11: "group",
    12: "loop",
    13: "multi-state-input",
    14: "multi-state-output",
    15: "notification-class",
    16: "program",
    17: "schedule",
    18: "averaging",
    19: "multi-state-value",
    20: "trend-log",
    21: "life-safety-point",
    22: "life-safety-zone",
    23: "accumulator",
    24: "pulse-converter",
    25: "event-log",
    26: "global-group",
    27: "trend-log-multiple",
    28: "load-control",
    29: "structured-view",
    30: "access-door",
    56: "network-port",
}

# Object types that drive physical equipment. A property write to one of these is an
# actuator command, not a configuration read.
COMMANDABLE_OBJECT_TYPES = frozenset({1, 4, 7, 14, 16, 17, 28})

REINITIALIZE_STATES = {
    0: "coldstart",
    1: "warmstart",
    2: "startbackup",
    3: "endbackup",
    4: "startrestore",
    5: "endrestore",
    6: "abortrestore",
    7: "activatechanges",
}

DEVICE_COMMUNICATION_STATES = {
    0: "enable",
    1: "disable",
    2: "disable-initiation",
}

# Services whose use is operationally significant in an OT network: they change device
# state, move files, or set clocks. A file-centric carver has no way to surface these, so
# they are recorded as observations instead.
SENSITIVE_CONFIRMED_SERVICES = {
    6: "File read from device - possible configuration or data exfiltration",
    7: "File write to device - firmware or configuration modification",
    10: "Object created on device",
    11: "Object deleted from device",
    15: "Property write - setpoint or actuator command",
    16: "Multiple property writes - setpoint or actuator commands",
    17: "Device communication control - can silence a device",
    18: "Vendor-proprietary transfer - opaque tunnelled payload",
    20: "Device reinitialization - coldstart/warmstart is disruptive",
    24: "Authentication attempt",
    25: "Encryption key request",
}

SENSITIVE_UNCONFIRMED_SERVICES = {
    4: "Vendor-proprietary transfer - opaque tunnelled payload",
    6: "Clock set on peers - affects scheduling and log correlation",
    9: "UTC clock set on peers - affects scheduling and log correlation",
    10: "Group write - bulk actuator command",
}

# Network-layer messages that rewrite routing tables or touch BACnet security material.
SENSITIVE_NETWORK_MESSAGES = {
    0x03: "Router rejected a message - possible routing disruption",
    0x06: "Routing table initialization - network topology modification",
    0x07: "Routing table initialization acknowledged",
    0x08: "Connection establishment to remote network",
    0x09: "Connection teardown to remote network",
    0x0D: "Security key update requested",
    0x0E: "Security key set update",
    0x0F: "Distribution key update",
    0x10: "Master key requested",
    0x11: "Master key set",
}

# Application tag numbers from the BACnet primitive-value encoding.
TAG_BOOLEAN = 1
TAG_UNSIGNED = 2
TAG_SIGNED = 3
TAG_OCTET_STRING = 6
TAG_CHARACTER_STRING = 7
TAG_ENUMERATED = 9
TAG_OBJECT_IDENTIFIER = 12

# A single Who-Is is routine; a device sweeping the network with them is enumerating it.
RECON_WHOIS_THRESHOLD = 100

MAX_OBSERVATIONS = 5000
MAX_DEVICES = 20000
MAX_PENDING_FILE_READS = 4096
MAX_FILE_ASSEMBLY_BYTES = 16 * 1024 * 1024
MAX_TAGS_PER_APDU = 128


def decode_object_id(raw: bytes) -> Optional[Tuple[int, int]]:
    if len(raw) != 4:
        return None
    value = struct.unpack("!I", raw)[0]
    return (value >> 22) & 0x3FF, value & 0x3FFFFF


def object_id_name(object_type: int, instance: int) -> str:
    return f"{OBJECT_TYPES.get(object_type, f'object-type-{object_type}')}:{instance}"


def read_tag(data: bytes, offset: int) -> Optional[Tuple[int, bool, int, bytes, int]]:
    """Decode one BACnet tag, returning (tag_number, is_context, lvt, value, next_offset)."""
    if offset >= len(data):
        return None

    control = data[offset]
    tag_number = control >> 4
    is_context = bool(control & 0x08)
    lvt = control & 0x07
    offset += 1

    if tag_number == 0x0F:
        if offset >= len(data):
            return None
        tag_number = data[offset]
        offset += 1

    # Opening (6) and closing (7) context tags delimit a construct and carry no value.
    if is_context and lvt in (6, 7):
        return tag_number, is_context, lvt, b"", offset

    # An application-tagged boolean encodes its value in the LVT field rather than a length.
    if not is_context and tag_number == TAG_BOOLEAN:
        return tag_number, is_context, lvt, b"", offset

    length = lvt
    if lvt == 5:
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
        if length == 254:
            if offset + 2 > len(data):
                return None
            length = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
        elif length == 255:
            if offset + 4 > len(data):
                return None
            length = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4

    if offset + length > len(data):
        return None
    return tag_number, is_context, lvt, data[offset:offset + length], offset + length


def iter_tags(data: bytes, offset: int = 0, limit: int = MAX_TAGS_PER_APDU) -> Iterator[Tuple[int, bool, int, bytes]]:
    seen = 0
    while offset < len(data) and seen < limit:
        tag = read_tag(data, offset)
        if tag is None:
            return
        tag_number, is_context, lvt, value, next_offset = tag
        yield tag_number, is_context, lvt, value
        if next_offset <= offset:
            return
        offset = next_offset
        seen += 1


class BacnetDecoder:
    def __init__(self, max_file_assembly_bytes: int = MAX_FILE_ASSEMBLY_BYTES):
        self.max_file_assembly_bytes = max_file_assembly_bytes
        self.bvlc_function_counts: Counter = Counter()
        self.apdu_type_counts: Counter = Counter()
        self.service_counts: Counter = Counter()
        self.network_message_counts: Counter = Counter()
        self.object_type_counts: Counter = Counter()
        self.whois_by_source: Counter = Counter()
        self.error_counts: Counter = Counter()
        self.reject_counts: Counter = Counter()
        self.abort_counts: Counter = Counter()
        self.malformed_packets = 0
        self.packets_decoded = 0
        self.devices: Dict[int, Dict[str, Any]] = {}
        self.observations: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._pending_file_reads: Dict[Tuple[str, str, int], Tuple[int, int]] = {}
        self._file_buffers: Dict[Tuple, Dict[str, Any]] = {}

    def handles(self, packet: Packet) -> bool:
        payload = packet.payload
        if packet.transport_proto != "UDP" or len(payload) < 4:
            return False
        if payload[0] != BVLC_TYPE_BACNET_IP:
            return False
        if payload[1] not in BVLC_FUNCTIONS:
            return False
        bvlc_len = struct.unpack("!H", payload[2:4])[0]
        return 4 <= bvlc_len <= len(payload)

    def process_packet(self, packet: Packet) -> List[Dict[str, Any]]:
        payload = packet.payload
        if not self.handles(packet):
            return []

        self.packets_decoded += 1
        function = payload[1]
        self.bvlc_function_counts[BVLC_FUNCTIONS[function]] += 1

        if function not in NPDU_BEARING_FUNCTIONS:
            return []

        bvlc_len = struct.unpack("!H", payload[2:4])[0]
        header_extra = NPDU_BEARING_FUNCTIONS[function]

        # A forwarded NPDU was relayed by a BBMD or router, so the UDP source is the relay
        # rather than the device. The originating B/IP address (4-byte IP, 2-byte port) sits
        # between the BVLC header and the NPDU; prefer it when attributing device identity.
        origin_ip = None
        if header_extra == 6 and len(payload) >= 10:
            origin_ip = ".".join(str(octet) for octet in payload[4:8])

        npdu = payload[4 + header_extra:bvlc_len]
        parsed = self._parse_npdu(npdu)
        if parsed is None:
            self.malformed_packets += 1
            return []

        apdu, network_message_type = parsed

        if network_message_type is not None:
            name = NETWORK_MESSAGE_TYPES.get(network_message_type, f"network-message-0x{network_message_type:02x}")
            self.network_message_counts[name] += 1
            note = SENSITIVE_NETWORK_MESSAGES.get(network_message_type)
            if note:
                self._record_observation(name, note, packet)
            return []

        if not apdu:
            self.malformed_packets += 1
            return []

        return self._parse_apdu(apdu, packet, origin_ip)

    def _parse_npdu(self, npdu: bytes) -> Optional[Tuple[bytes, Optional[int]]]:
        if len(npdu) < 2 or npdu[0] != 0x01:
            return None

        control = npdu[1]
        offset = 2
        has_destination = bool(control & 0x20)

        if has_destination:
            if offset + 3 > len(npdu):
                return None
            offset += 3 + npdu[offset + 2]

        if control & 0x08:
            if offset + 3 > len(npdu):
                return None
            offset += 3 + npdu[offset + 2]

        # Hop count is only present when a destination address is, and follows both addresses.
        if has_destination:
            offset += 1

        if offset > len(npdu):
            return None

        if control & 0x80:
            if offset >= len(npdu):
                return None
            return b"", npdu[offset]

        return npdu[offset:], None

    def _parse_apdu(self, apdu: bytes, packet: Packet, origin_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        pdu_type = apdu[0] >> 4
        self.apdu_type_counts[APDU_TYPES.get(pdu_type, f"apdu-type-{pdu_type}")] += 1

        if pdu_type == APDU_CONFIRMED_REQUEST:
            return self._parse_confirmed_request(apdu, packet)
        if pdu_type == APDU_UNCONFIRMED_REQUEST:
            return self._parse_unconfirmed_request(apdu, packet, origin_ip)
        if pdu_type == APDU_COMPLEX_ACK:
            return self._parse_complex_ack(apdu, packet)
        if pdu_type == APDU_ERROR:
            self._parse_error(apdu, packet)
        elif pdu_type in (APDU_REJECT, APDU_ABORT):
            self._parse_reject_or_abort(apdu, pdu_type, packet)
        return []

    def _parse_error(self, apdu: bytes, packet: Packet):
        # PDU type 5: invoke ID, error choice (the service that failed), then class and code.
        if len(apdu) < 3:
            self.malformed_packets += 1
            return

        service = apdu[2]
        service_name = CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
        self.service_counts[f"{service_name}-error"] += 1

        error_class = None
        error_code = None
        for tag_number, is_context, _lvt, value in iter_tags(apdu[3:], limit=4):
            if is_context or tag_number != TAG_ENUMERATED or not value:
                continue
            if error_class is None:
                error_class = int.from_bytes(value, "big")
            elif error_code is None:
                error_code = int.from_bytes(value, "big")
                break

        if error_class is None:
            return

        class_name = ERROR_CLASSES.get(error_class, f"error-class-{error_class}")
        self.error_counts[f"{class_name}/code-{error_code}"] += 1
        if error_class == 4:
            self._record_observation(
                f"{service_name}-error",
                "Security error returned - authentication or authorization failure",
                packet,
                f"error class security, code {error_code}",
            )

    def _parse_reject_or_abort(self, apdu: bytes, pdu_type: int, packet: Packet):
        if len(apdu) < 3:
            self.malformed_packets += 1
            return

        reason = apdu[2]
        if pdu_type == APDU_REJECT:
            name = REJECT_REASONS.get(reason, f"reject-reason-{reason}")
            self.reject_counts[name] += 1
            if reason in PROBING_REJECT_REASONS:
                self._record_observation(
                    "reject",
                    "Service rejected as unrecognized or malformed - consistent with protocol probing",
                    packet,
                    name,
                )
        else:
            name = ABORT_REASONS.get(reason, f"abort-reason-{reason}")
            self.abort_counts[name] += 1

    def _parse_confirmed_request(self, apdu: bytes, packet: Packet) -> List[Dict[str, Any]]:
        segmented = bool(apdu[0] & 0x08)
        # byte 1 holds max-segments/max-APDU, byte 2 the invoke ID, then the segmentation
        # fields when present, and finally the service choice.
        service_offset = 5 if segmented else 3
        if len(apdu) <= service_offset:
            self.malformed_packets += 1
            return []

        invoke_id = apdu[2]
        service = apdu[service_offset]
        service_name = CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}")
        self.service_counts[service_name] += 1

        note = SENSITIVE_CONFIRMED_SERVICES.get(service)
        if note is None:
            # readProperty/readPropertyMultiple dominate a polling capture; stop here so the
            # hot path stays cheap.
            return []

        body = apdu[service_offset + 1:]
        detail = None
        candidates: List[Dict[str, Any]] = []

        if service == SERVICE_ATOMIC_READ_FILE:
            file_oid = self._first_object_id(body)
            if file_oid is not None:
                self._remember_file_read(packet, invoke_id, file_oid)
                detail = f"file {object_id_name(*file_oid)}"
        elif service == SERVICE_ATOMIC_WRITE_FILE:
            file_oid = self._first_object_id(body)
            if file_oid is not None:
                detail = f"file {object_id_name(*file_oid)}"
                candidates.extend(self._absorb_file_data(body, packet, file_oid, "write"))
        elif service == 20:
            state = self._first_enumerated(body)
            if state is not None:
                detail = f"state {REINITIALIZE_STATES.get(state, state)}"
        elif service == 17:
            state = self._first_enumerated(body)
            if state is not None:
                detail = f"state {DEVICE_COMMUNICATION_STATES.get(state, state)}"
        elif service in (15, 16):
            detail = self._describe_write_target(body)

        self._record_observation(service_name, note, packet, detail)
        return candidates

    def _parse_unconfirmed_request(self, apdu: bytes, packet: Packet, origin_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        if len(apdu) < 2:
            self.malformed_packets += 1
            return []

        service = apdu[1]
        service_name = UNCONFIRMED_SERVICES.get(service, f"unconfirmed-service-{service}")
        self.service_counts[service_name] += 1
        body = apdu[2:]

        if service == 0:
            self._record_i_am(body, packet, origin_ip)
            return []

        if service == 8:
            self.whois_by_source[packet.src_ip] += 1
            return []

        note = SENSITIVE_UNCONFIRMED_SERVICES.get(service)
        if note:
            self._record_observation(service_name, note, packet)
        return []

    def _parse_complex_ack(self, apdu: bytes, packet: Packet) -> List[Dict[str, Any]]:
        segmented = bool(apdu[0] & 0x08)
        # byte 1 is the invoke ID, then the segmentation fields when present, then the
        # service ACK choice.
        service_offset = 4 if segmented else 2
        if len(apdu) <= service_offset:
            self.malformed_packets += 1
            return []

        invoke_id = apdu[1]
        service = apdu[service_offset]
        self.service_counts[CONFIRMED_SERVICES.get(service, f"confirmed-service-{service}") + "-ack"] += 1

        if service != SERVICE_ATOMIC_READ_FILE:
            return []

        # The ACK carries no file identifier; it is matched to the request by invoke ID.
        file_oid = self._pending_file_reads.pop((packet.dst_ip, packet.src_ip, invoke_id), None)
        if file_oid is None:
            return []

        return self._absorb_file_data(apdu[service_offset + 1:], packet, file_oid, "read")

    def _first_object_id(self, body: bytes) -> Optional[Tuple[int, int]]:
        for tag_number, is_context, _lvt, value in iter_tags(body):
            if not is_context and tag_number == TAG_OBJECT_IDENTIFIER:
                return decode_object_id(value)
        return None

    def _first_enumerated(self, body: bytes) -> Optional[int]:
        for tag_number, is_context, _lvt, value in iter_tags(body):
            if tag_number in (TAG_ENUMERATED, TAG_UNSIGNED) and value:
                return int.from_bytes(value, "big")
        return None

    def _describe_write_target(self, body: bytes) -> Optional[str]:
        object_id = self._first_object_id(body)
        if object_id is None:
            # writeProperty encodes the object identifier in context tag 0.
            for tag_number, is_context, _lvt, value in iter_tags(body):
                if is_context and tag_number == 0 and len(value) == 4:
                    object_id = decode_object_id(value)
                    break
        if object_id is None:
            return None

        object_type, instance = object_id
        self.object_type_counts[OBJECT_TYPES.get(object_type, f"object-type-{object_type}")] += 1
        target = object_id_name(object_type, instance)
        if object_type in COMMANDABLE_OBJECT_TYPES:
            return f"commandable object {target}"
        return f"object {target}"

    def _record_i_am(self, body: bytes, packet: Packet, origin_ip: Optional[str] = None):
        values = list(iter_tags(body))
        device_instance = None
        numbers: List[int] = []
        for tag_number, is_context, _lvt, value in values:
            if is_context:
                continue
            if tag_number == TAG_OBJECT_IDENTIFIER:
                object_id = decode_object_id(value)
                if object_id and object_id[0] == 8:
                    device_instance = object_id[1]
            elif tag_number in (TAG_UNSIGNED, TAG_ENUMERATED) and value:
                numbers.append(int.from_bytes(value, "big"))

        if device_instance is None or len(self.devices) >= MAX_DEVICES:
            return

        # I-Am carries max-APDU-length, segmentation-supported and vendor-id, in that order.
        address = origin_ip or packet.src_ip
        record = self.devices.setdefault(device_instance, {
            "device_instance": device_instance,
            "address": address,
            "first_seen": packet.timestamp,
        })
        record["address"] = address
        if origin_ip and origin_ip != packet.src_ip:
            record["relayed_by"] = packet.src_ip
        if len(numbers) >= 1:
            record["max_apdu_length"] = numbers[0]
        if len(numbers) >= 2:
            record["segmentation_supported"] = numbers[1]
        if len(numbers) >= 3:
            record["vendor_id"] = numbers[2]

    def _remember_file_read(self, packet: Packet, invoke_id: int, file_oid: Tuple[int, int]):
        if len(self._pending_file_reads) >= MAX_PENDING_FILE_READS:
            self._pending_file_reads.clear()
        self._pending_file_reads[(packet.src_ip, packet.dst_ip, invoke_id)] = file_oid

    def _absorb_file_data(
        self,
        body: bytes,
        packet: Packet,
        file_oid: Tuple[int, int],
        direction: str,
    ) -> List[Dict[str, Any]]:
        end_of_file = False
        start_position: Optional[int] = None
        chunks: List[bytes] = []

        for tag_number, is_context, lvt, value in iter_tags(body):
            if is_context:
                continue
            if tag_number == TAG_BOOLEAN:
                end_of_file = bool(lvt)
            elif tag_number == TAG_SIGNED and start_position is None and value:
                start_position = int.from_bytes(value, "big", signed=True)
            elif tag_number == TAG_OCTET_STRING and value:
                chunks.append(value)

        if not chunks and not end_of_file:
            return []

        key = (direction, packet.src_ip, packet.dst_ip, file_oid)
        buffer = self._file_buffers.get(key)
        if buffer is None:
            buffer = {
                "data": bytearray(),
                "flow": packet.flow_key,
                "timestamp": packet.timestamp,
                "file_oid": file_oid,
                "direction": direction,
                "truncated": False,
            }
            self._file_buffers[key] = buffer

        position = start_position if start_position is not None else len(buffer["data"])
        for chunk in chunks:
            # Keep whatever fits under the cap rather than dropping the chunk outright, so a
            # transfer larger than the budget still yields the bytes seen first.
            room = self.max_file_assembly_bytes - position
            if room <= 0:
                buffer["truncated"] = True
                break
            if len(chunk) > room:
                chunk = chunk[:room]
                buffer["truncated"] = True

            end = position + len(chunk)
            if end > len(buffer["data"]):
                buffer["data"].extend(b"\x00" * (end - len(buffer["data"])))
            buffer["data"][position:end] = chunk
            position = end

        if end_of_file:
            return self._flush_file_buffer(key)
        return []

    def _flush_file_buffer(self, key: Tuple) -> List[Dict[str, Any]]:
        buffer = self._file_buffers.pop(key, None)
        if buffer is None or not buffer["data"]:
            return []

        object_type, instance = buffer["file_oid"]
        return [{
            "data": bytes(buffer["data"]),
            "filename": f"bacnet_{object_id_name(object_type, instance).replace(':', '_')}.bin",
            "source_protocol": "BACNET_ATOMIC_FILE",
            "flow": buffer["flow"],
            "timestamp": buffer["timestamp"],
            "metadata": {
                "bacnet_file_object": object_id_name(object_type, instance),
                "transfer_direction": buffer["direction"],
                "truncated": buffer["truncated"],
            },
        }]

    def finalize(self) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for key in list(self._file_buffers):
            candidates.extend(self._flush_file_buffer(key))
        self._pending_file_reads.clear()
        return candidates

    def _record_observation(self, service_name: str, note: str, packet: Packet, detail: Optional[str] = None):
        key = (service_name, packet.src_ip or "", packet.dst_ip or "")
        record = self.observations.get(key)
        if record is None:
            if len(self.observations) >= MAX_OBSERVATIONS:
                return
            record = {
                "service": service_name,
                "note": note,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "count": 0,
                "first_seen": packet.timestamp,
                "last_seen": packet.timestamp,
                "details": [],
            }
            self.observations[key] = record

        record["count"] += 1
        record["last_seen"] = packet.timestamp
        if detail and detail not in record["details"] and len(record["details"]) < 8:
            record["details"].append(detail)

    def summary(self) -> Dict[str, Any]:
        scanners = [
            {"src_ip": ip, "who_is_count": count}
            for ip, count in self.whois_by_source.most_common()
            if count >= RECON_WHOIS_THRESHOLD
        ]
        observations = sorted(self.observations.values(), key=lambda r: r["count"], reverse=True)
        return {
            "packets_decoded": self.packets_decoded,
            "malformed_packets": self.malformed_packets,
            "bvlc_functions": dict(self.bvlc_function_counts),
            "apdu_types": dict(self.apdu_type_counts),
            "services": dict(self.service_counts.most_common()),
            "errors": dict(self.error_counts.most_common()),
            "rejects": dict(self.reject_counts.most_common()),
            "aborts": dict(self.abort_counts.most_common()),
            "network_messages": dict(self.network_message_counts),
            "commanded_object_types": dict(self.object_type_counts.most_common()),
            "devices": sorted(self.devices.values(), key=lambda d: d["device_instance"]),
            "observations": observations,
            "enumeration_sources": scanners,
        }
