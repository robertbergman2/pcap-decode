import unittest

from pcap_decode.analyzer import MalwareAnalyzer
from pcap_decode.models import FlowKey, ThreatLevel
from tests.pcap_builder import make_dummy_pe


class TestMalwareAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = MalwareAnalyzer()

    def test_analyze_suspicious_pe(self):
        pe_data = make_dummy_pe(payload_strings=[b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"http://malicious-c2.net/gate.php"])
        flow = FlowKey("192.168.1.100", 49200, "104.244.42.1", 80)

        result = self.analyzer.analyze_payload(
            raw_data=pe_data,
            source_proto="HTTP",
            flow=flow,
            filename="trojan.exe",
        )

        self.assertEqual(result.extension, "exe")
        self.assertIn("PE Executable", result.magic_type)
        self.assertIn(result.threat_level, (ThreatLevel.HIGH, ThreatLevel.CRITICAL))
        self.assertTrue(any("VirtualAlloc" in ind for ind in result.threat_indicators))
        self.assertTrue(any("http://malicious-c2.net/gate.php" in url for url in result.metadata.get("embedded_urls", [])))

    def test_analyze_high_entropy_blob(self):
        import os
        random_bytes = os.urandom(4096)
        result = self.analyzer.analyze_payload(
            raw_data=random_bytes,
            source_proto="RAW_TCP",
            filename="blob.bin",
        )

        self.assertGreater(result.entropy, 7.5)
        self.assertTrue(any("High entropy" in ind for ind in result.threat_indicators))

    def test_analyze_powershell_payload(self):
        script = b"powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
        result = self.analyzer.analyze_payload(
            raw_data=script,
            source_proto="HTTP",
            filename="stage1.ps1",
        )

        self.assertIn("PowerShell", result.magic_type)
        self.assertIn(result.threat_level, (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL))


if __name__ == "__main__":
    unittest.main()
