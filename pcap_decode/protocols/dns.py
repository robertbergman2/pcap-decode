import base64
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

from pcap_decode.models import Packet


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    visited_offsets = set()
    initial_offset = offset
    jumped = False
    max_jumps = 10

    while offset < len(data) and max_jumps > 0:
        if offset in visited_offsets:
            break
        visited_offsets.add(offset)

        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                initial_offset = offset + 2
                jumped = True
            offset = ptr
            max_jumps -= 1
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("latin1", errors="replace"))
            offset += length

    domain = ".".join(labels)
    final_offset = initial_offset if jumped else offset
    return domain, final_offset


class DnsDecoder:
    def __init__(self):
        self.suspicious_domains: List[Dict[str, Any]] = []

    def process_packet(self, packet: Packet) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        payload = packet.payload
        if packet.transport_proto not in ("UDP", "TCP") or not payload:
            return extracted

        if packet.src_port != 53 and packet.dst_port != 53:
            return extracted

        dns_data = payload
        if packet.transport_proto == "TCP" and len(payload) >= 2:
            tcp_len = struct.unpack("!H", payload[:2])[0]
            if len(payload) >= tcp_len + 2:
                dns_data = payload[2:tcp_len + 2]

        if len(dns_data) < 12:
            return extracted

        try:
            txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_data[:12])
            offset = 12

            queries = []
            for _ in range(qdcount):
                if offset >= len(dns_data):
                    break
                dname, offset = parse_dns_name(dns_data, offset)
                if offset + 4 <= len(dns_data):
                    qtype, qclass = struct.unpack("!HH", dns_data[offset:offset + 4])
                    offset += 4
                    queries.append((dname, qtype, qclass))
                    self._check_suspicious_domain(dname, packet)

            for _ in range(ancount):
                if offset >= len(dns_data):
                    break
                dname, offset = parse_dns_name(dns_data, offset)
                if offset + 10 > len(dns_data):
                    break
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", dns_data[offset:offset + 10])
                offset += 10
                if offset + rdlen > len(dns_data):
                    break
                rdata = dns_data[offset:offset + rdlen]
                offset += rdlen

                if rtype == 16:
                    txt_payload = bytearray()
                    txt_off = 0
                    while txt_off < len(rdata):
                        tlen = rdata[txt_off]
                        txt_off += 1
                        txt_payload.extend(rdata[txt_off:txt_off + tlen])
                        txt_off += tlen
                    
                    raw_txt = bytes(txt_payload)
                    decoded_blob = None
                    try:
                        candidate = raw_txt.strip()
                        if len(candidate) > 20 and len(candidate) % 4 == 0:
                            decoded_blob = base64.b64decode(candidate)
                    except Exception:
                        pass

                    target_data = decoded_blob if decoded_blob else raw_txt
                    if len(target_data) >= 32:
                        extracted.append({
                            "data": target_data,
                            "filename": f"dns_txt_{dname[:20]}.bin",
                            "source_protocol": "DNS",
                            "flow": packet.flow_key,
                            "timestamp": packet.timestamp,
                            "metadata": {
                                "dns_domain": dname,
                                "record_type": "TXT",
                                "raw_txt": raw_txt.decode("latin1", errors="replace"),
                            },
                        })

        except Exception:
            pass

        return extracted

    def _check_suspicious_domain(self, domain: str, packet: Packet):
        if not domain:
            return
        subdomain = domain.split(".")[0] if "." in domain else domain
        if len(subdomain) > 35:
            ent = calculate_entropy(subdomain.encode("ascii", errors="ignore"))
            if ent > 3.5:
                self.suspicious_domains.append({
                    "domain": domain,
                    "subdomain": subdomain,
                    "length": len(subdomain),
                    "entropy": ent,
                    "timestamp": packet.timestamp,
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                })
