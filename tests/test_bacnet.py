import struct
import unittest

from pcap_decode.models import Packet
from pcap_decode.protocols.bacnet import (
    BacnetDecoder,
    decode_object_id,
    iter_tags,
    read_tag,
)
from tests.pcap_builder import (
    build_bacnet_app_tag,
    build_bacnet_atomic_file_body,
    build_bacnet_complex_ack,
    build_bacnet_confirmed_request,
    build_bacnet_object_id,
    build_bacnet_unconfirmed_request,
    build_bvlc,
    build_npdu,
)


def make_udp_packet(payload: bytes, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2",
                    src_port: int = 47808, dst_port: int = 47808, frame_number: int = 1,
                    timestamp: float = 100.0) -> Packet:
    return Packet(
        frame_number=frame_number,
        timestamp=timestamp,
        link_type=1,
        raw_data=b"",
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_proto=17,
        transport_proto="UDP",
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
    )


class TestBacnetTagDecoding(unittest.TestCase):
    def test_read_application_tag(self):
        encoded = build_bacnet_app_tag(2, b"\x01\x02")
        tag_number, is_context, lvt, value, next_offset = read_tag(encoded, 0)
        self.assertEqual(tag_number, 2)
        self.assertFalse(is_context)
        self.assertEqual(value, b"\x01\x02")
        self.assertEqual(next_offset, len(encoded))

    def test_read_extended_length_tag(self):
        payload = b"A" * 300
        encoded = build_bacnet_app_tag(6, payload)
        tag_number, _is_context, _lvt, value, next_offset = read_tag(encoded, 0)
        self.assertEqual(tag_number, 6)
        self.assertEqual(value, payload)
        self.assertEqual(next_offset, len(encoded))

    def test_boolean_value_lives_in_lvt(self):
        tag_number, is_context, lvt, value, next_offset = read_tag(bytes([(1 << 4) | 1]), 0)
        self.assertEqual(tag_number, 1)
        self.assertFalse(is_context)
        self.assertEqual(lvt, 1)
        self.assertEqual(value, b"")
        self.assertEqual(next_offset, 1)

    def test_context_opening_and_closing_tags_carry_no_value(self):
        opening = read_tag(bytes([(0 << 4) | 0x08 | 6]), 0)
        self.assertEqual(opening[0], 0)
        self.assertTrue(opening[1])
        self.assertEqual(opening[4], 1)

        closing = read_tag(bytes([(0 << 4) | 0x08 | 7]), 0)
        self.assertTrue(closing[1])
        self.assertEqual(closing[4], 1)

    def test_truncated_tag_returns_none(self):
        self.assertIsNone(read_tag(b"", 0))
        # Declares two value bytes but supplies one.
        self.assertIsNone(read_tag(bytes([(2 << 4) | 2, 0x01]), 0))

    def test_iter_tags_stops_on_malformed_data(self):
        good = build_bacnet_app_tag(2, b"\x05")
        tags = list(iter_tags(good + bytes([(2 << 4) | 4, 0x01])))
        self.assertEqual(len(tags), 1)

    def test_decode_object_id(self):
        raw = struct.pack("!I", (8 << 22) | 12345)
        self.assertEqual(decode_object_id(raw), (8, 12345))
        self.assertIsNone(decode_object_id(b"\x01\x02"))


class TestBacnetHandles(unittest.TestCase):
    def setUp(self):
        self.decoder = BacnetDecoder()

    def test_handles_bvlc_on_nonstandard_port(self):
        packet = make_udp_packet(
            build_bacnet_confirmed_request(14),
            src_port=47809,
            dst_port=47807,
        )
        self.assertTrue(self.decoder.handles(packet))

    def test_rejects_non_bacnet_payload(self):
        self.assertFalse(self.decoder.handles(make_udp_packet(b"LEI\x05\x02\xff\x09\xc6" * 4)))

    def test_rejects_unknown_bvlc_function(self):
        payload = struct.pack("!BBH", 0x81, 0x7F, 8) + b"\x01\x00\x10\x08"
        self.assertFalse(self.decoder.handles(make_udp_packet(payload)))

    def test_rejects_inconsistent_length(self):
        payload = struct.pack("!BBH", 0x81, 0x0A, 400) + b"\x01\x00"
        self.assertFalse(self.decoder.handles(make_udp_packet(payload)))

    def test_rejects_tcp(self):
        packet = make_udp_packet(build_bacnet_confirmed_request(14))
        packet.transport_proto = "TCP"
        self.assertFalse(self.decoder.handles(packet))


class TestBacnetServiceDecoding(unittest.TestCase):
    def setUp(self):
        self.decoder = BacnetDecoder()

    def test_read_property_multiple_is_counted_but_not_flagged(self):
        packet = make_udp_packet(build_bacnet_confirmed_request(14))
        self.assertEqual(self.decoder.process_packet(packet), [])

        summary = self.decoder.summary()
        self.assertEqual(summary["services"]["readPropertyMultiple"], 1)
        self.assertEqual(summary["observations"], [])
        self.assertEqual(summary["malformed_packets"], 0)

    def test_reinitialize_device_is_flagged_with_state(self):
        # reinitializedStateOfDevice enumerated 1 == warmstart
        body = build_bacnet_app_tag(9, b"\x01")
        self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(20, body)))

        observations = self.decoder.summary()["observations"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["service"], "reinitializeDevice")
        self.assertIn("warmstart", observations[0]["details"][0])

    def test_device_communication_control_is_flagged(self):
        body = build_bacnet_app_tag(9, b"\x01")
        self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(17, body)))

        observations = self.decoder.summary()["observations"]
        self.assertEqual(observations[0]["service"], "deviceCommunicationControl")
        self.assertIn("disable", observations[0]["details"][0])

    def test_write_property_to_commandable_object_is_identified(self):
        # writeProperty encodes the target object identifier in context tag 0.
        body = bytes([0x08 | 0x04]) + struct.pack("!I", (4 << 22) | 7)
        self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(15, body)))

        observations = self.decoder.summary()["observations"]
        self.assertEqual(observations[0]["service"], "writeProperty")
        self.assertIn("commandable object binary-output:7", observations[0]["details"][0])

    def test_private_transfer_is_flagged(self):
        self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(18)))
        self.assertEqual(self.decoder.summary()["observations"][0]["service"], "confirmedPrivateTransfer")

    def test_observations_aggregate_by_service_and_peer(self):
        body = build_bacnet_app_tag(9, b"\x00")
        for i in range(5):
            self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(20, body), frame_number=i))

        observations = self.decoder.summary()["observations"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["count"], 5)

    def test_who_is_volume_flags_enumeration(self):
        payload = build_bacnet_unconfirmed_request(8)
        for i in range(120):
            self.decoder.process_packet(make_udp_packet(payload, frame_number=i))

        summary = self.decoder.summary()
        self.assertEqual(summary["services"]["who-Is"], 120)
        self.assertEqual(summary["enumeration_sources"][0]["src_ip"], "10.0.0.1")
        self.assertEqual(summary["enumeration_sources"][0]["who_is_count"], 120)

    def test_single_who_is_is_not_enumeration(self):
        self.decoder.process_packet(make_udp_packet(build_bacnet_unconfirmed_request(8)))
        self.assertEqual(self.decoder.summary()["enumeration_sources"], [])

    def test_i_am_builds_device_inventory(self):
        body = (
            build_bacnet_object_id(8, 4711)
            + build_bacnet_app_tag(2, b"\x01\xe0")   # max APDU 480
            + build_bacnet_app_tag(9, b"\x03")       # segmentation: no-segmentation
            + build_bacnet_app_tag(2, b"\x00\x18")   # vendor id 24
        )
        self.decoder.process_packet(make_udp_packet(build_bacnet_unconfirmed_request(0, body)))

        devices = self.decoder.summary()["devices"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["device_instance"], 4711)
        self.assertEqual(devices[0]["max_apdu_length"], 480)
        self.assertEqual(devices[0]["vendor_id"], 24)
        self.assertEqual(devices[0]["address"], "10.0.0.1")

    def test_forwarded_i_am_attributes_device_to_originator(self):
        body = (
            build_bacnet_object_id(8, 857002)
            + build_bacnet_app_tag(2, b"\x32")
            + build_bacnet_app_tag(9, b"\x03")
            + build_bacnet_app_tag(2, b"\x01\x25")
        )
        apdu = bytes([0x10, 0]) + body
        npdu = bytes([0x01, 0x00]) + apdu
        # forwarded-npdu carries the originating device's B/IP address (IP then port).
        payload = (
            struct.pack("!BBH", 0x81, 0x04, 4 + 6 + len(npdu))
            + bytes([130, 20, 7, 99]) + struct.pack("!H", 47808)
            + npdu
        )
        self.decoder.process_packet(make_udp_packet(payload, src_ip="130.20.7.45"))

        devices = self.decoder.summary()["devices"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["address"], "130.20.7.99")
        self.assertEqual(devices[0]["relayed_by"], "130.20.7.45")

    def test_unicast_i_am_has_no_relay_recorded(self):
        body = build_bacnet_object_id(8, 12) + build_bacnet_app_tag(2, b"\x32")
        self.decoder.process_packet(make_udp_packet(build_bacnet_unconfirmed_request(0, body)))

        devices = self.decoder.summary()["devices"]
        self.assertEqual(devices[0]["address"], "10.0.0.1")
        self.assertNotIn("relayed_by", devices[0])

    def test_network_layer_message_is_flagged(self):
        # NPDU control bit 0x80 marks a network-layer message; 0x06 is Initialize-Routing-Table.
        payload = build_bvlc(bytes([0x01, 0x80, 0x06]))
        self.decoder.process_packet(make_udp_packet(payload))

        summary = self.decoder.summary()
        self.assertEqual(summary["network_messages"]["Initialize-Routing-Table"], 1)
        self.assertEqual(summary["observations"][0]["service"], "Initialize-Routing-Table")

    def test_forwarded_npdu_skips_originating_address(self):
        apdu = bytes([0x00, 0x05, 1, 14])
        npdu = bytes([0x01, 0x00]) + apdu
        # forwarded-npdu (0x04) prefixes a 6-byte B/IP address before the NPDU.
        payload = struct.pack("!BBH", 0x81, 0x04, 4 + 6 + len(npdu)) + b"\x0a\x00\x00\x63\xba\xc0" + npdu
        self.decoder.process_packet(make_udp_packet(payload))

        summary = self.decoder.summary()
        self.assertEqual(summary["bvlc_functions"]["forwarded-npdu"], 1)
        self.assertEqual(summary["services"]["readPropertyMultiple"], 1)

    def test_npdu_with_routing_addresses_locates_apdu(self):
        apdu = bytes([0x00, 0x05, 1, 20]) + build_bacnet_app_tag(9, b"\x00")
        # Control 0x28: destination present (DNET/DLEN/DADR) + source present, plus hop count.
        npdu = (
            bytes([0x01, 0x28])
            + struct.pack("!HB", 5, 1) + b"\x0a"
            + struct.pack("!HB", 9, 1) + b"\x0b"
            + bytes([255])
            + apdu
        )
        self.decoder.process_packet(make_udp_packet(build_bvlc(npdu)))

        summary = self.decoder.summary()
        self.assertEqual(summary["services"]["reinitializeDevice"], 1)
        self.assertEqual(summary["malformed_packets"], 0)

    def test_error_pdu_names_the_failed_service(self):
        # PDU type 5: invoke ID, error choice, then error class and code enumerations.
        apdu = bytes([0x50, 1, 14]) + build_bacnet_app_tag(9, b"\x01") + build_bacnet_app_tag(9, b"\x1f")
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(apdu))))

        summary = self.decoder.summary()
        self.assertEqual(summary["services"]["readPropertyMultiple-error"], 1)
        self.assertEqual(summary["errors"]["object/code-31"], 1)
        self.assertEqual(summary["observations"], [])

    def test_security_error_is_flagged(self):
        apdu = bytes([0x50, 1, 15]) + build_bacnet_app_tag(9, b"\x04") + build_bacnet_app_tag(9, b"\x19")
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(apdu))))

        observations = self.decoder.summary()["observations"]
        self.assertEqual(observations[0]["service"], "writeProperty-error")
        self.assertIn("security", observations[0]["details"][0])

    def test_unrecognized_service_reject_is_flagged_as_probing(self):
        apdu = bytes([0x60, 1, 9])
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(apdu))))

        summary = self.decoder.summary()
        self.assertEqual(summary["rejects"]["unrecognized-service"], 1)
        self.assertEqual(summary["observations"][0]["service"], "reject")

    def test_routine_reject_is_counted_but_not_flagged(self):
        apdu = bytes([0x60, 1, 6])
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(apdu))))

        summary = self.decoder.summary()
        self.assertEqual(summary["rejects"]["parameter-out-of-range"], 1)
        self.assertEqual(summary["observations"], [])

    def test_abort_reason_is_counted(self):
        apdu = bytes([0x70, 1, 10])
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(apdu))))
        self.assertEqual(self.decoder.summary()["aborts"]["tsm-timeout"], 1)

    def test_malformed_apdu_is_counted_not_raised(self):
        # Confirmed request truncated before the service choice byte.
        self.decoder.process_packet(make_udp_packet(build_bvlc(build_npdu(bytes([0x00, 0x05])))))
        self.assertEqual(self.decoder.summary()["malformed_packets"], 1)


class TestBacnetFileExtraction(unittest.TestCase):
    def setUp(self):
        self.decoder = BacnetDecoder()

    def test_atomic_read_file_extracts_payload(self):
        request = build_bacnet_confirmed_request(6, build_bacnet_object_id(10, 3), invoke_id=42)
        self.assertEqual(self.decoder.process_packet(make_udp_packet(request)), [])

        file_data = b"MZ" + b"\x90" * 200
        ack = build_bacnet_complex_ack(6, build_bacnet_atomic_file_body(file_data), invoke_id=42)
        # The ACK travels back from the device, so source and destination are swapped.
        results = self.decoder.process_packet(
            make_udp_packet(ack, src_ip="10.0.0.2", dst_ip="10.0.0.1")
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["data"], file_data)
        self.assertEqual(results[0]["source_protocol"], "BACNET_ATOMIC_FILE")
        self.assertEqual(results[0]["metadata"]["bacnet_file_object"], "file:3")
        self.assertEqual(results[0]["metadata"]["transfer_direction"], "read")

    def test_atomic_read_file_ack_without_request_is_ignored(self):
        ack = build_bacnet_complex_ack(6, build_bacnet_atomic_file_body(b"X" * 64), invoke_id=9)
        self.assertEqual(self.decoder.process_packet(make_udp_packet(ack)), [])

    def test_chunked_read_reassembles_by_start_position(self):
        request = build_bacnet_confirmed_request(6, build_bacnet_object_id(10, 1), invoke_id=7)
        self.decoder.process_packet(make_udp_packet(request))

        first = build_bacnet_complex_ack(
            6, build_bacnet_atomic_file_body(b"AAAA", start_position=0, end_of_file=False), invoke_id=7
        )
        results = self.decoder.process_packet(make_udp_packet(first, src_ip="10.0.0.2", dst_ip="10.0.0.1"))
        self.assertEqual(results, [])

        # A second chunk needs its own matching request, since the first ACK consumed the pending entry.
        self.decoder.process_packet(make_udp_packet(request))
        second = build_bacnet_complex_ack(
            6, build_bacnet_atomic_file_body(b"BBBB", start_position=4, end_of_file=True), invoke_id=7
        )
        results = self.decoder.process_packet(make_udp_packet(second, src_ip="10.0.0.2", dst_ip="10.0.0.1"))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["data"], b"AAAABBBB")

    def test_atomic_write_file_extracts_payload(self):
        body = build_bacnet_object_id(10, 5) + build_bacnet_atomic_file_body(b"CONFIG=1\n" * 8)
        results = self.decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(7, body)))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["metadata"]["transfer_direction"], "write")
        self.assertIn(b"CONFIG=1", results[0]["data"])
        self.assertEqual(self.decoder.summary()["observations"][0]["service"], "atomicWriteFile")

    def test_finalize_flushes_incomplete_transfer(self):
        request = build_bacnet_confirmed_request(6, build_bacnet_object_id(10, 2), invoke_id=3)
        self.decoder.process_packet(make_udp_packet(request))
        partial = build_bacnet_complex_ack(
            6, build_bacnet_atomic_file_body(b"PARTIAL", end_of_file=False), invoke_id=3
        )
        self.decoder.process_packet(make_udp_packet(partial, src_ip="10.0.0.2", dst_ip="10.0.0.1"))

        pending = self.decoder.finalize()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["data"], b"PARTIAL")
        self.assertEqual(self.decoder.finalize(), [])

    def test_assembly_size_is_capped(self):
        decoder = BacnetDecoder(max_file_assembly_bytes=16)
        body = build_bacnet_object_id(10, 9) + build_bacnet_atomic_file_body(b"Z" * 64)
        results = decoder.process_packet(make_udp_packet(build_bacnet_confirmed_request(7, body)))

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["metadata"]["truncated"])
        self.assertLessEqual(len(results[0]["data"]), 16)


if __name__ == "__main__":
    unittest.main()
