import base64
import unittest

from pcap_decode.models import FlowKey, TcpStream
from pcap_decode.protocols.email import EmailDecoder


class TestEmailDecoder(unittest.TestCase):
    def test_smtp_base64_attachment_extraction(self):
        decoder = EmailDecoder()
        malware_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b64_payload = base64.b64encode(malware_bytes).decode("ascii")

        raw_smtp = (
            "EHLO victim-pc\r\n"
            "MAIL FROM:<attacker@bad.org>\r\n"
            "RCPT TO:<user@target.corp>\r\n"
            "DATA\r\n"
            "From: attacker@bad.org\r\n"
            "To: user@target.corp\r\n"
            "Subject: Urgent Invoice\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="BOUNDARY123"\r\n\r\n'
            "--BOUNDARY123\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "Please find invoice attached.\r\n"
            "--BOUNDARY123\r\n"
            "Content-Type: application/octet-stream\r\n"
            'Content-Disposition: attachment; filename="Invoice_2026.exe"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{b64_payload}\r\n"
            "--BOUNDARY123--\r\n"
            ".\r\n"
        ).encode("latin1")

        stream = TcpStream(
            flow=FlowKey("192.168.1.15", 55432, "10.0.0.25", 25),
            start_time=100.0,
            end_time=102.0,
            client_to_server=raw_smtp,
            server_to_client=b"220 mail.target.corp ESMTP\r\n250 OK\r\n250 OK\r\n250 OK\r\n354 End data with <CR><LF>.<CR><LF>\r\n250 OK: queued\r\n",
        )

        extracted = decoder.parse_stream(stream)
        self.assertEqual(len(extracted), 1)
        item = extracted[0]
        self.assertEqual(item["filename"], "Invoice_2026.exe")
        self.assertEqual(item["data"], malware_bytes)
        self.assertEqual(item["source_protocol"], "SMTP")
        self.assertEqual(item["metadata"]["from"], "attacker@bad.org")
        self.assertEqual(item["metadata"]["subject"], "Urgent Invoice")


if __name__ == "__main__":
    unittest.main()
