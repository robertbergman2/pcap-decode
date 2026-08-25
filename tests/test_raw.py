import unittest

from pcap_decode.models import Packet
from pcap_decode.protocols.raw import (
    MAX_RAW_UDP_CANDIDATES_PER_FLOW,
    RawStreamDecoder,
)


def make_udp_packet(payload: bytes, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2",
                    src_port: int = 40000, dst_port: int = 40001, frame_number: int = 1) -> Packet:
    return Packet(
        frame_number=frame_number,
        timestamp=100.0,
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


class TestRawUdpGating(unittest.TestCase):
    def setUp(self):
        self.decoder = RawStreamDecoder()
        self.payload = b"P" * 64

    def test_unknown_udp_flow_still_carves(self):
        results = self.decoder.parse_udp_packet(make_udp_packet(self.payload))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source_protocol"], "RAW_UDP")
        self.assertEqual(results[0]["data"], self.payload)

    def test_short_payload_is_skipped_without_counting_suppression(self):
        self.assertEqual(self.decoder.parse_udp_packet(make_udp_packet(b"tiny")), [])
        self.assertEqual(self.decoder.suppression_summary()["raw_udp_packets_suppressed"], 0)

    def test_telemetry_ports_are_suppressed(self):
        for port in (123, 161, 5353, 44818, 34962):
            decoder = RawStreamDecoder()
            self.assertEqual(decoder.parse_udp_packet(make_udp_packet(self.payload, dst_port=port)), [])
            summary = decoder.suppression_summary()
            self.assertEqual(summary["raw_udp_packets_suppressed"], 1)
            self.assertEqual(summary["by_reason"], {"telemetry_port": 1})

    def test_telemetry_port_matches_either_direction(self):
        self.assertEqual(self.decoder.parse_udp_packet(make_udp_packet(self.payload, src_port=123)), [])
        self.assertEqual(self.decoder.suppression_summary()["by_reason"], {"telemetry_port": 1})

    def test_per_flow_cap_limits_a_chatty_flow(self):
        emitted = 0
        for i in range(50):
            emitted += len(self.decoder.parse_udp_packet(make_udp_packet(self.payload, frame_number=i)))

        self.assertEqual(emitted, MAX_RAW_UDP_CANDIDATES_PER_FLOW)
        summary = self.decoder.suppression_summary()
        self.assertEqual(summary["by_reason"], {"per_flow_cap": 50 - MAX_RAW_UDP_CANDIDATES_PER_FLOW})
        self.assertEqual(summary["tracked_udp_flows"], 1)

    def test_cap_is_shared_across_both_directions_of_a_flow(self):
        for i in range(MAX_RAW_UDP_CANDIDATES_PER_FLOW):
            self.decoder.parse_udp_packet(make_udp_packet(self.payload, frame_number=i))

        reverse = make_udp_packet(
            self.payload, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=40001, dst_port=40000
        )
        self.assertEqual(self.decoder.parse_udp_packet(reverse), [])

    def test_distinct_flows_get_independent_budgets(self):
        first = sum(len(self.decoder.parse_udp_packet(make_udp_packet(self.payload, dst_port=40001)))
                    for _ in range(50))
        second = sum(len(self.decoder.parse_udp_packet(make_udp_packet(self.payload, dst_port=40002)))
                     for _ in range(50))

        self.assertEqual(first, MAX_RAW_UDP_CANDIDATES_PER_FLOW)
        self.assertEqual(second, MAX_RAW_UDP_CANDIDATES_PER_FLOW)
        self.assertEqual(self.decoder.suppression_summary()["tracked_udp_flows"], 2)

    def test_flow_table_cap_stops_tracking_and_reports_it(self):
        decoder = RawStreamDecoder(max_tracked_udp_flows=2)
        for port in (50001, 50002):
            self.assertEqual(len(decoder.parse_udp_packet(make_udp_packet(self.payload, dst_port=port))), 1)

        self.assertEqual(decoder.parse_udp_packet(make_udp_packet(self.payload, dst_port=50003)), [])
        summary = decoder.suppression_summary()
        self.assertEqual(summary["by_reason"], {"flow_table_full": 1})
        self.assertEqual(summary["tracked_udp_flows"], 2)

    def test_tcp_stream_carving_is_unchanged(self):
        from pcap_decode.models import FlowKey, TcpStream

        stream = TcpStream(
            flow=FlowKey("10.0.0.1", 1234, "10.0.0.2", 4444),
            start_time=1.0,
            end_time=2.0,
            client_to_server=b"C" * 32,
            server_to_client=b"S" * 32,
            packets_count=4,
        )
        results = self.decoder.parse_stream(stream)
        self.assertEqual(len(results), 2)
        self.assertEqual({r["source_protocol"] for r in results}, {"RAW_TCP"})


if __name__ == "__main__":
    unittest.main()
