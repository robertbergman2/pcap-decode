import re
from typing import Any, Dict, List, Optional, Tuple

from pcap_decode.models import FlowKey, TcpStream


class FtpSessionState:
    def __init__(self):
        self.control_flow: Optional[FlowKey] = None
        self.pending_transfers: List[Tuple[str, str, int]] = []


class FtpDecoder:
    def __init__(self):
        self.data_port_map: Dict[Tuple[str, int], str] = {}

    def register_control_stream(self, stream: TcpStream):
        c2s = stream.client_to_server.decode("latin1", errors="replace")
        s2c = stream.server_to_client.decode("latin1", errors="replace")

        pasv_matches = re.findall(r"227 Entering Passive Mode \((\d+,\d+,\d+,\d+,\d+,\d+)\)", s2c)
        retr_matches = re.findall(r"(?:RETR|STOR)\s+([^\r\n]+)", c2s, re.IGNORECASE)

        for match in pasv_matches:
            nums = [int(n) for n in match.split(",")]
            if len(nums) == 6:
                ip = f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
                port = (nums[4] << 8) + nums[5]
                fn = retr_matches.pop(0) if retr_matches else "ftp_file.bin"
                self.data_port_map[(ip, port)] = fn.strip()

        port_matches = re.findall(r"PORT\s+(\d+,\d+,\d+,\d+,\d+,\d+)", c2s, re.IGNORECASE)
        for match in port_matches:
            nums = [int(n) for n in match.split(",")]
            if len(nums) == 6:
                ip = f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
                port = (nums[4] << 8) + nums[5]
                fn = retr_matches.pop(0) if retr_matches else "ftp_file.bin"
                self.data_port_map[(ip, port)] = fn.strip()

    def parse_stream(self, stream: TcpStream) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        c2s = stream.client_to_server
        s2c = stream.server_to_client

        if stream.flow.src_port == 21 or stream.flow.dst_port == 21:
            self.register_control_stream(stream)
            return extracted

        data_payload = s2c if len(s2c) > len(c2s) else c2s
        if not data_payload:
            return extracted

        key1 = (stream.flow.dst_ip, stream.flow.dst_port)
        key2 = (stream.flow.src_ip, stream.flow.src_port)
        filename = self.data_port_map.get(key1) or self.data_port_map.get(key2)

        if filename or stream.flow.src_port == 20 or stream.flow.dst_port == 20:
            extracted.append({
                "data": data_payload,
                "filename": filename or "ftp_transfer.bin",
                "source_protocol": "FTP",
                "flow": stream.flow,
                "timestamp": stream.start_time,
                "metadata": {
                    "ftp_filename": filename,
                },
            })

        return extracted
