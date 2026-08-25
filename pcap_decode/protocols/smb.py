import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from pcap_decode.models import TcpStream

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"

SMB2_CMD_CREATE = 0x0005
SMB2_CMD_READ = 0x0008
SMB2_CMD_WRITE = 0x0009


class SmbDecoder:
    def __init__(self):
        self.file_names: Dict[Tuple[int, bytes], str] = {}
        self.file_buffers: Dict[Tuple[int, bytes], bytearray] = defaultdict(bytearray)

    def parse_stream(self, stream: TcpStream) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        if stream.flow.src_port not in (445, 139) and stream.flow.dst_port not in (445, 139):
            return extracted

        c2s_messages = self._parse_netbios_messages(stream.client_to_server)
        s2c_messages = self._parse_netbios_messages(stream.server_to_client)

        active_files: Dict[str, bytearray] = defaultdict(bytearray)

        for msg in c2s_messages:
            if msg.startswith(SMB2_MAGIC) and len(msg) >= 64:
                cmd = struct.unpack("<H", msg[12:14])[0]
                session_id = struct.unpack("<Q", msg[40:48])[0]
                
                if cmd == SMB2_CMD_CREATE and len(msg) >= 120:
                    name_offset = struct.unpack("<H", msg[116:118])[0]
                    name_length = struct.unpack("<H", msg[118:120])[0]
                    if 0 < name_offset < len(msg) and name_length > 0:
                        raw_name = msg[name_offset:name_offset + name_length]
                        try:
                            fname = raw_name.decode("utf-16le", errors="ignore").strip("\x00")
                            if fname:
                                clean_name = fname.split("\\")[-1]
                                if clean_name:
                                    self.file_names[(session_id, b"")] = clean_name
                        except Exception:
                            pass
                elif cmd == SMB2_CMD_WRITE and len(msg) >= 112:
                    data_offset = struct.unpack("<H", msg[72:74])[0]
                    data_length = struct.unpack("<I", msg[76:80])[0]
                    if 0 < data_offset < len(msg) and data_length > 0:
                        file_id = msg[88:104]
                        data = msg[data_offset:data_offset + data_length]
                        target_key = (session_id, file_id)
                        active_files[f"write_{session_id}_{file_id.hex()}"].extend(data)

        for msg in s2c_messages:
            if msg.startswith(SMB2_MAGIC) and len(msg) >= 64:
                cmd = struct.unpack("<H", msg[12:14])[0]
                session_id = struct.unpack("<Q", msg[40:48])[0]
                if cmd == SMB2_CMD_READ and len(msg) >= 80:
                    data_offset = struct.unpack("<B", msg[66:67])[0]
                    data_length = struct.unpack("<I", msg[68:72])[0]
                    if 0 < data_offset < len(msg) and data_length > 0:
                        data = msg[data_offset:data_offset + data_length]
                        active_files[f"read_{session_id}"].extend(data)

        for k, data_bytes in active_files.items():
            if len(data_bytes) > 0:
                extracted.append({
                    "data": bytes(data_bytes),
                    "filename": f"smb_transfer_{k}.bin",
                    "source_protocol": "SMB",
                    "flow": stream.flow,
                    "timestamp": stream.start_time,
                    "metadata": {
                        "smb_key": k,
                        "size": len(data_bytes),
                    },
                })

        return extracted

    def _parse_netbios_messages(self, data: bytes) -> List[bytes]:
        messages: List[bytes] = []
        offset = 0
        while offset + 4 <= len(data):
            msg_type = data[offset]
            msg_len = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
            if msg_len == 0 or offset + 4 + msg_len > len(data):
                if offset == 0 and len(data) > 64 and (data.startswith(SMB2_MAGIC) or data.startswith(SMB1_MAGIC)):
                    messages.append(data)
                break
            msg_body = data[offset + 4:offset + 4 + msg_len]
            messages.append(msg_body)
            offset += 4 + msg_len
        return messages
