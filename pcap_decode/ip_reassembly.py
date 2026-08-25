from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from pcap_decode.models import Packet


class IpDefragmenter:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.fragments: Dict[Tuple[str, str, int, int], List[Tuple[int, bool, bytes, float]]] = defaultdict(list)

    def process(self, packet: Packet) -> Optional[Packet]:
        if packet.ip_version != 4 or (packet.ip_frag_offset == 0 and not packet.ip_more_frags):
            return packet

        if not packet.src_ip or not packet.dst_ip or packet.ip_proto is None or packet.ip_id is None:
            return packet

        key = (packet.src_ip, packet.dst_ip, packet.ip_proto, packet.ip_id)
        self.fragments[key].append((packet.ip_frag_offset, packet.ip_more_frags, packet.payload, packet.timestamp))

        frags = self.fragments[key]
        has_last = any(not mf for _, mf, _, _ in frags)
        if not has_last:
            return None

        frags_sorted = sorted(frags, key=lambda x: x[0])
        curr_offset = 0
        rebuilt = bytearray()
        
        for offset, mf, data, _ in frags_sorted:
            if offset > curr_offset:
                return None
            overlap = curr_offset - offset
            if overlap < len(data):
                chunk = data[overlap:]
                rebuilt.extend(chunk)
                curr_offset += len(chunk)
            if not mf and offset + len(data) == curr_offset:
                del self.fragments[key]
                new_pkt = Packet(
                    frame_number=packet.frame_number,
                    timestamp=packet.timestamp,
                    link_type=packet.link_type,
                    raw_data=packet.raw_data,
                    ip_version=4,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    ip_proto=packet.ip_proto,
                    ip_id=packet.ip_id,
                    ip_frag_offset=0,
                    ip_more_frags=False,
                    transport_proto=packet.transport_proto,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    seq_num=packet.seq_num,
                    ack_num=packet.ack_num,
                    tcp_flags=packet.tcp_flags,
                    payload=bytes(rebuilt),
                )
                return new_pkt

        return None
