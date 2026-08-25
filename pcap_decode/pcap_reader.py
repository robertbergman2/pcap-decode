import socket
import struct
from typing import BinaryIO, Generator, List, Optional, Tuple, Union

from pcap_decode.models import Packet

PCAP_MAGIC_MICRO_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_MICRO_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP_12 = 12
LINKTYPE_RAW_IP_14 = 14
LINKTYPE_RAW_IP_101 = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6_HOPOPT = 0
IPPROTO_IPV6_ROUTE = 43
IPPROTO_IPV6_FRAG = 44
IPPROTO_IPV6_OPTS = 60


def parse_ipv4(data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int], int, bool, bytes]:
    if len(data) < 20:
        return None, None, None, 0, False, b""
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl:
        return None, None, None, 0, False, b""
    
    total_len = struct.unpack("!H", data[2:4])[0]
    ip_id = struct.unpack("!H", data[4:6])[0]
    flags_fo = struct.unpack("!H", data[6:8])[0]
    more_frags = bool(flags_fo & 0x2000)
    frag_offset = (flags_fo & 0x1FFF) * 8
    
    proto = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    
    payload_end = min(len(data), total_len) if total_len > 0 else len(data)
    payload = data[ihl:payload_end]
    return src_ip, dst_ip, proto, frag_offset, more_frags, payload


def parse_ipv6(data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int], bytes]:
    if len(data) < 40:
        return None, None, None, b""
    payload_len, next_header = struct.unpack("!HB", data[4:7])
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    
    current_offset = 40
    current_proto = next_header
    
    while current_offset < len(data):
        if current_proto in (IPPROTO_IPV6_HOPOPT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_OPTS):
            if len(data) < current_offset + 2:
                break
            nxt, hdr_len = data[current_offset], data[current_offset + 1]
            ext_len = (hdr_len + 1) * 8
            current_proto = nxt
            current_offset += ext_len
        elif current_proto == IPPROTO_IPV6_FRAG:
            if len(data) < current_offset + 8:
                break
            nxt = data[current_offset]
            current_proto = nxt
            current_offset += 8
        else:
            break
            
    payload = data[current_offset:]
    return src_ip, dst_ip, current_proto, payload


def parse_tcp(data: bytes) -> Tuple[int, int, int, int, dict, bytes]:
    if len(data) < 20:
        return 0, 0, 0, 0, {}, b""
    src_port, dst_port, seq, ack, offset_reserved, flags_byte = struct.unpack("!HHIIBB", data[:14])
    data_offset = ((offset_reserved >> 4) & 0x0F) * 4
    if len(data) < data_offset:
        return src_port, dst_port, seq, ack, {}, b""
    
    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
        "ECE": bool(flags_byte & 0x40),
        "CWR": bool(flags_byte & 0x80),
    }
    payload = data[data_offset:]
    return src_port, dst_port, seq, ack, flags, payload


def parse_udp(data: bytes) -> Tuple[int, int, bytes]:
    if len(data) < 8:
        return 0, 0, b""
    src_port, dst_port, length = struct.unpack("!HHH", data[:6])
    payload = data[8:length] if length >= 8 and len(data) >= length else data[8:]
    return src_port, dst_port, payload


class PcapReader:
    def __init__(self, filepath_or_stream: Union[str, BinaryIO]):
        self.filepath_or_stream = filepath_or_stream
        self._file: Optional[BinaryIO] = None
        self._own_file = False

    def __enter__(self):
        if isinstance(self.filepath_or_stream, str):
            self._file = open(self.filepath_or_stream, "rb")
            self._own_file = True
        else:
            self._file = self.filepath_or_stream
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._own_file and self._file:
            self._file.close()

    def packets(self) -> Generator[Packet, None, None]:
        if self._file is None:
            if isinstance(self.filepath_or_stream, str):
                with open(self.filepath_or_stream, "rb") as f:
                    self._file = f
                    yield from self._read_all()
                    self._file = None
            else:
                self._file = self.filepath_or_stream
                yield from self._read_all()
        else:
            yield from self._read_all()

    def _read_all(self) -> Generator[Packet, None, None]:
        magic = self._file.read(4)
        if not magic:
            return

        if magic == PCAPNG_SHB_MAGIC:
            yield from self._read_pcapng(magic)
        elif magic in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_NANO_LE, PCAP_MAGIC_NANO_BE):
            yield from self._read_pcap(magic)
        else:
            raise ValueError(f"Unknown packet capture format / magic bytes: {magic.hex()}")

    def _read_pcap(self, magic: bytes) -> Generator[Packet, None, None]:
        if magic in (PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_NANO_LE):
            endian = "<"
        else:
            endian = ">"
        
        is_nano = magic in (PCAP_MAGIC_NANO_LE, PCAP_MAGIC_NANO_BE)
        time_div = 1e9 if is_nano else 1e6

        hdr_data = self._file.read(20)
        if len(hdr_data) < 20:
            return

        ver_major, ver_minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
            f"{endian}HHiIII", hdr_data
        )

        frame_num = 0
        while True:
            pkt_hdr = self._file.read(16)
            if len(pkt_hdr) < 16:
                break
            
            frame_num += 1
            ts_sec, ts_usec, caplen, origlen = struct.unpack(f"{endian}IIII", pkt_hdr)
            timestamp = ts_sec + (ts_usec / time_div)
            
            pkt_data = self._file.read(caplen)
            if len(pkt_data) < caplen:
                break
                
            packet = self._decode_packet(frame_num, timestamp, linktype, pkt_data)
            if packet:
                yield packet

    def _read_pcapng(self, initial_magic: bytes) -> Generator[Packet, None, None]:
        hdr_rem = self._file.read(8)
        if len(hdr_rem) < 8:
            return
        
        block_len, bom = struct.unpack("<II", hdr_rem)
        if bom == 0x1A2B3C4D:
            endian = "<"
        else:
            endian = ">"
            block_len = struct.unpack(">I", hdr_rem[:4])[0]

        skip_len = block_len - 12
        if skip_len > 0:
            self._file.read(skip_len)

        interfaces = []
        frame_num = 0

        while True:
            block_header = self._file.read(8)
            if len(block_header) < 8:
                break
            
            b_type, b_len = struct.unpack(f"{endian}II", block_header)
            if b_len < 12:
                break
                
            b_body_len = b_len - 12
            b_body = self._file.read(b_body_len)
            trailer = self._file.read(4)
            if len(b_body) < b_body_len or len(trailer) < 4:
                break

            if b_type == 0x00000001:
                if len(b_body) >= 8:
                    link_type, snap_len = struct.unpack(f"{endian}H2xI", b_body[:8])
                    interfaces.append({"link_type": link_type, "snap_len": snap_len, "ts_resol": 1e6})
            elif b_type == 0x00000006:
                if len(b_body) >= 20:
                    if_id, ts_high, ts_low, caplen, origlen = struct.unpack(f"{endian}IIIII", b_body[:20])
                    link_type = interfaces[if_id]["link_type"] if if_id < len(interfaces) else LINKTYPE_ETHERNET
                    ts_resol = interfaces[if_id]["ts_resol"] if if_id < len(interfaces) else 1e6
                    
                    ts_raw = (ts_high << 32) | ts_low
                    timestamp = ts_raw / ts_resol
                    
                    pkt_data = b_body[20:20 + caplen]
                    frame_num += 1
                    packet = self._decode_packet(frame_num, timestamp, link_type, pkt_data)
                    if packet:
                        yield packet
            elif b_type == 0x00000003:
                if len(b_body) >= 4:
                    origlen = struct.unpack(f"{endian}I", b_body[:4])[0]
                    link_type = interfaces[0]["link_type"] if interfaces else LINKTYPE_ETHERNET
                    caplen = min(len(b_body) - 4, origlen)
                    pkt_data = b_body[4:4 + caplen]
                    frame_num += 1
                    packet = self._decode_packet(frame_num, 0.0, link_type, pkt_data)
                    if packet:
                        yield packet

    def _decode_packet(self, frame_num: int, timestamp: float, link_type: int, raw_data: bytes) -> Optional[Packet]:
        packet = Packet(
            frame_number=frame_num,
            timestamp=timestamp,
            link_type=link_type,
            raw_data=raw_data,
        )

        ip_data = b""
        ethertype = None

        if link_type == LINKTYPE_ETHERNET:
            if len(raw_data) < 14:
                return packet
            ethertype = struct.unpack("!H", raw_data[12:14])[0]
            offset = 14
            while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(raw_data) >= offset + 4:
                ethertype = struct.unpack("!H", raw_data[offset + 2:offset + 4])[0]
                offset += 4
            ip_data = raw_data[offset:]
        elif link_type == LINKTYPE_LINUX_SLL:
            if len(raw_data) < 16:
                return packet
            ethertype = struct.unpack("!H", raw_data[14:16])[0]
            ip_data = raw_data[16:]
        elif link_type == LINKTYPE_LINUX_SLL2:
            if len(raw_data) < 20:
                return packet
            ethertype = struct.unpack("!H", raw_data[0:2])[0]
            ip_data = raw_data[20:]
        elif link_type in (LINKTYPE_RAW_IP_12, LINKTYPE_RAW_IP_14, LINKTYPE_RAW_IP_101):
            if not raw_data:
                return packet
            ver = (raw_data[0] >> 4) & 0x0F
            ethertype = ETHERTYPE_IPV4 if ver == 4 else (ETHERTYPE_IPV6 if ver == 6 else None)
            ip_data = raw_data
        elif link_type == LINKTYPE_NULL:
            if len(raw_data) < 4:
                return packet
            family = struct.unpack("=I", raw_data[:4])[0]
            ethertype = ETHERTYPE_IPV4 if family == 2 else (ETHERTYPE_IPV6 if family in (24, 28, 30) else None)
            ip_data = raw_data[4:]
        else:
            if len(raw_data) >= 20:
                ver = (raw_data[0] >> 4) & 0x0F
                if ver == 4:
                    ethertype = ETHERTYPE_IPV4
                    ip_data = raw_data
                elif ver == 6:
                    ethertype = ETHERTYPE_IPV6
                    ip_data = raw_data

        if ethertype == ETHERTYPE_IPV4:
            src_ip, dst_ip, proto, frag_off, more_frags, l4_data = parse_ipv4(ip_data)
            packet.ip_version = 4
            packet.src_ip = src_ip
            packet.dst_ip = dst_ip
            packet.ip_proto = proto
            packet.ip_frag_offset = frag_off
            packet.ip_more_frags = more_frags

            if proto == IPPROTO_TCP:
                packet.transport_proto = "TCP"
                sp, dp, seq, ack, flags, payload = parse_tcp(l4_data)
                packet.src_port = sp
                packet.dst_port = dp
                packet.seq_num = seq
                packet.ack_num = ack
                packet.tcp_flags = flags
                packet.payload = payload
            elif proto == IPPROTO_UDP:
                packet.transport_proto = "UDP"
                sp, dp, payload = parse_udp(l4_data)
                packet.src_port = sp
                packet.dst_port = dp
                packet.payload = payload
            elif proto == IPPROTO_ICMP:
                packet.transport_proto = "ICMP"
                packet.payload = l4_data

        elif ethertype == ETHERTYPE_IPV6:
            src_ip, dst_ip, proto, l4_data = parse_ipv6(ip_data)
            packet.ip_version = 6
            packet.src_ip = src_ip
            packet.dst_ip = dst_ip
            packet.ip_proto = proto

            if proto == IPPROTO_TCP:
                packet.transport_proto = "TCP"
                sp, dp, seq, ack, flags, payload = parse_tcp(l4_data)
                packet.src_port = sp
                packet.dst_port = dp
                packet.seq_num = seq
                packet.ack_num = ack
                packet.tcp_flags = flags
                packet.payload = payload
            elif proto == IPPROTO_UDP:
                packet.transport_proto = "UDP"
                sp, dp, payload = parse_udp(l4_data)
                packet.src_port = sp
                packet.dst_port = dp
                packet.payload = payload

        return packet
