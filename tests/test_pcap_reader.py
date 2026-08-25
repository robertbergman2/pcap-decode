import os
import tempfile
import unittest

from pcap_decode.pcap_reader import PcapReader
from tests.pcap_builder import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_tcp_packet,
    build_udp_packet,
    create_pcap_file,
    create_pcapng_file,
)


class TestPcapReader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_read_classic_pcap(self):
        pcap_path = os.path.join(self.temp_dir.name, "test_classic.pcap")
        
        ip_payload = build_tcp_packet(12345, 80, 1000, 0, {"SYN": True}, b"")
        ip_pkt = build_ipv4_packet("192.168.1.100", "93.184.216.34", 6, ip_payload)
        eth_frame = build_ethernet_frame(ip_pkt)

        create_pcap_file(pcap_path, [(100.0, eth_frame)])

        with PcapReader(pcap_path) as reader:
            packets = list(reader.packets())

        self.assertEqual(len(packets), 1)
        pkt = packets[0]
        self.assertEqual(pkt.frame_number, 1)
        self.assertEqual(pkt.src_ip, "192.168.1.100")
        self.assertEqual(pkt.dst_ip, "93.184.216.34")
        self.assertEqual(pkt.transport_proto, "TCP")
        self.assertEqual(pkt.src_port, 12345)
        self.assertEqual(pkt.dst_port, 80)
        self.assertTrue(pkt.tcp_flags["SYN"])

    def test_read_pcapng(self):
        pcapng_path = os.path.join(self.temp_dir.name, "test_ng.pcapng")

        udp_payload = build_udp_packet(5353, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
        ip_pkt = build_ipv4_packet("10.0.0.5", "8.8.8.8", 17, udp_payload)
        eth_frame = build_ethernet_frame(ip_pkt)

        create_pcapng_file(pcapng_path, [(200.5, eth_frame)])

        with PcapReader(pcapng_path) as reader:
            packets = list(reader.packets())

        self.assertEqual(len(packets), 1)
        pkt = packets[0]
        self.assertEqual(pkt.frame_number, 1)
        self.assertEqual(pkt.src_ip, "10.0.0.5")
        self.assertEqual(pkt.dst_ip, "8.8.8.8")
        self.assertEqual(pkt.transport_proto, "UDP")
        self.assertEqual(pkt.src_port, 5353)
        self.assertEqual(pkt.dst_port, 53)
        self.assertEqual(len(pkt.payload), 29)


if __name__ == "__main__":
    unittest.main()
