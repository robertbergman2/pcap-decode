import os
import tempfile
import unittest

from pcap_decode.engine import PcapDecoderEngine
from tests.pcap_builder import (
    build_bacnet_atomic_file_body,
    build_bacnet_complex_ack,
    build_bacnet_confirmed_request,
    build_bacnet_object_id,
    build_ethernet_frame,
    build_ipv4_packet,
    build_udp_packet,
    create_pcap_file,
    make_dummy_pe,
)

BACNET_PORT = 47808


def bacnet_frame(payload: bytes, src_ip: str = "10.20.0.5", dst_ip: str = "10.20.0.9",
                 src_port: int = BACNET_PORT, dst_port: int = BACNET_PORT) -> bytes:
    return build_ethernet_frame(
        build_ipv4_packet(src_ip, dst_ip, 17, build_udp_packet(src_port, dst_port, payload))
    )


class TestOtCaptureHandling(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _decode(self, packets):
        pcap_path = os.path.join(self.temp_dir.name, "ot.pcap")
        create_pcap_file(pcap_path, packets)
        return PcapDecoderEngine().decode_file(pcap_path)

    def test_bacnet_polling_does_not_flood_extracted_files(self):
        """A BACnet poll loop must be decoded, not turned into one object per packet."""
        packets = []
        t = 1000.0
        for i in range(500):
            # Vary the payload so SHA256 dedup cannot mask a per-packet candidate explosion.
            body = build_bacnet_object_id(2, i)
            packets.append((t, bacnet_frame(build_bacnet_confirmed_request(14, body, invoke_id=i % 256))))
            t += 0.01

        result = self._decode(packets)

        self.assertEqual(result["packets_count"], 500)
        self.assertEqual(result["udp_packets_count"], 500)
        self.assertEqual(result["extracted_files_count"], 0)
        self.assertEqual(result["bacnet"]["packets_decoded"], 500)
        self.assertEqual(result["bacnet"]["services"]["readPropertyMultiple"], 500)
        # Claimed traffic is never handed to the raw carver, so nothing is "suppressed" either.
        self.assertEqual(result["raw_carving"]["raw_udp_packets_suppressed"], 0)

    def test_bacnet_on_nonstandard_port_is_still_claimed(self):
        packets = [
            (1000.0 + i * 0.01, bacnet_frame(build_bacnet_confirmed_request(14), src_port=47809, dst_port=47807))
            for i in range(100)
        ]
        result = self._decode(packets)

        self.assertEqual(result["bacnet"]["packets_decoded"], 100)
        self.assertEqual(result["extracted_files_count"], 0)

    def test_unknown_chatty_udp_protocol_is_capped(self):
        packets = []
        t = 1000.0
        for i in range(200):
            payload = b"LEI\x05\x02" + i.to_bytes(2, "big") + b"\xff" * 40
            packets.append((t, bacnet_frame(payload, src_port=2056, dst_port=2056)))
            t += 0.01

        result = self._decode(packets)

        # Not BACnet and not a known telemetry port, so the per-flow cap is what bounds it.
        self.assertEqual(result["bacnet"]["packets_decoded"], 0)
        self.assertLessEqual(result["extracted_files_count"], 8)
        self.assertEqual(result["raw_carving"]["by_reason"], {"per_flow_cap": 192})

    def test_bacnet_file_transfer_payload_is_extracted_and_analyzed(self):
        pe_payload = make_dummy_pe(payload_strings=[b"VirtualAlloc", b"WriteProcessMemory"])
        request = build_bacnet_confirmed_request(6, build_bacnet_object_id(10, 1), invoke_id=11)
        ack = build_bacnet_complex_ack(6, build_bacnet_atomic_file_body(pe_payload), invoke_id=11)

        result = self._decode([
            (1000.0, bacnet_frame(request, src_ip="10.20.0.5", dst_ip="10.20.0.9")),
            (1000.1, bacnet_frame(ack, src_ip="10.20.0.9", dst_ip="10.20.0.5")),
        ])

        self.assertEqual(result["extracted_files_count"], 1)
        extracted = result["extracted_files"][0]
        self.assertEqual(extracted.source_protocol, "BACNET_ATOMIC_FILE")
        self.assertEqual(extracted.data, pe_payload)
        # Reaching the analyzer is the point: a PE moved over BACnet should not read as benign.
        self.assertIn("PE", extracted.magic_type)
        self.assertGreater(extracted.threat_score, 0)

    def test_device_control_activity_reaches_the_report(self):
        reinit = build_bacnet_confirmed_request(20, bytes([(9 << 4) | 1, 0x00]))
        result = self._decode([(1000.0, bacnet_frame(reinit))])

        observations = result["bacnet"]["observations"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["service"], "reinitializeDevice")
        self.assertIn("coldstart", observations[0]["details"][0])

    def test_dns_is_still_claimed_and_not_raw_carved(self):
        query = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01" + b"\x00" * 32
        )
        frame = build_ethernet_frame(
            build_ipv4_packet("10.20.0.5", "8.8.8.8", 17, build_udp_packet(53124, 53, query))
        )
        result = self._decode([(1000.0, frame)])

        self.assertEqual(result["extracted_files_count"], 0)
        self.assertEqual(result["raw_carving"]["raw_udp_packets_suppressed"], 0)

    def test_no_carve_raw_still_decodes_bacnet_files(self):
        request = build_bacnet_confirmed_request(6, build_bacnet_object_id(10, 4), invoke_id=2)
        ack = build_bacnet_complex_ack(6, build_bacnet_atomic_file_body(b"SETPOINT=72\n" * 8), invoke_id=2)
        pcap_path = os.path.join(self.temp_dir.name, "no_carve.pcap")
        create_pcap_file(pcap_path, [
            (1000.0, bacnet_frame(request, src_ip="10.20.0.5", dst_ip="10.20.0.9")),
            (1000.1, bacnet_frame(ack, src_ip="10.20.0.9", dst_ip="10.20.0.5")),
        ])

        result = PcapDecoderEngine(carve_raw_streams=False).decode_file(pcap_path)
        self.assertEqual(result["extracted_files_count"], 1)
        self.assertEqual(result["extracted_files"][0].source_protocol, "BACNET_ATOMIC_FILE")


if __name__ == "__main__":
    unittest.main()
