import unittest

from pcap_decode.models import FlowKey, Packet
from pcap_decode.tcp_reassembly import DirectionalReassembler, TcpReassembler


class TestTcpReassembly(unittest.TestCase):
    def test_in_order_reassembly(self):
        reassembler = DirectionalReassembler()
        reassembler.add_segment(100, b"Hello ", {"SYN": False}, 1.0, 1)
        reassembler.add_segment(106, b"World!", {"SYN": False}, 2.0, 2)
        
        self.assertEqual(reassembler.get_data(), b"Hello World!")

    def test_out_of_order_reassembly(self):
        reassembler = DirectionalReassembler()
        reassembler.add_segment(106, b"World!", {"SYN": False}, 2.0, 2)
        reassembler.add_segment(100, b"Hello ", {"SYN": False}, 1.0, 1)

        self.assertEqual(reassembler.get_data(), b"Hello World!")

    def test_overlapping_retransmissions(self):
        reassembler = DirectionalReassembler()
        reassembler.add_segment(100, b"ABCDEF", {"SYN": False}, 1.0, 1)
        reassembler.add_segment(104, b"EFGHIJ", {"SYN": False}, 2.0, 2)

        self.assertEqual(reassembler.get_data(), b"ABCDEFGHIJ")

    def test_full_stream_bidirectional(self):
        tracker = TcpReassembler()
        
        p1 = Packet(
            frame_number=1, timestamp=10.0, link_type=1, raw_data=b"",
            ip_version=4, src_ip="192.168.1.50", dst_ip="10.0.0.1", ip_proto=6,
            transport_proto="TCP", src_port=50000, dst_port=80,
            seq_num=1000, ack_num=0, tcp_flags={"SYN": True}, payload=b""
        )
        p2 = Packet(
            frame_number=2, timestamp=10.1, link_type=1, raw_data=b"",
            ip_version=4, src_ip="192.168.1.50", dst_ip="10.0.0.1", ip_proto=6,
            transport_proto="TCP", src_port=50000, dst_port=80,
            seq_num=1001, ack_num=2001, tcp_flags={"PSH": True, "ACK": True},
            payload=b"GET /malware.exe HTTP/1.1\r\nHost: test.com\r\n\r\n"
        )
        p3 = Packet(
            frame_number=3, timestamp=10.2, link_type=1, raw_data=b"",
            ip_version=4, src_ip="10.0.0.1", dst_ip="192.168.1.50", ip_proto=6,
            transport_proto="TCP", src_port=80, dst_port=50000,
            seq_num=2001, ack_num=1045, tcp_flags={"PSH": True, "ACK": True},
            payload=b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nTEST"
        )
        p4 = Packet(
            frame_number=4, timestamp=10.3, link_type=1, raw_data=b"",
            ip_version=4, src_ip="10.0.0.1", dst_ip="192.168.1.50", ip_proto=6,
            transport_proto="TCP", src_port=80, dst_port=50000,
            seq_num=2045, ack_num=1045, tcp_flags={"FIN": True, "ACK": True},
            payload=b""
        )

        tracker.process_packet(p1)
        tracker.process_packet(p2)
        tracker.process_packet(p3)
        tracker.process_packet(p4)

        streams = list(tracker.finalize())
        self.assertEqual(len(streams), 1)
        s = streams[0]
        self.assertIn(b"GET /malware.exe", s.client_to_server)
        self.assertIn(b"HTTP/1.1 200 OK", s.server_to_client)
        self.assertIn(b"TEST", s.server_to_client)


if __name__ == "__main__":
    unittest.main()
