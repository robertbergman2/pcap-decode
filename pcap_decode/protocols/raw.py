from collections import Counter
from typing import Any, Dict, List, Optional

from pcap_decode.models import FlowKey, Packet, TcpStream

# UDP services that are continuous machine-to-machine chatter: discovery, time sync,
# telemetry, and OT process I/O. None of them carry transferable files, so emitting one
# raw candidate per packet only floods the report -- a 32-minute BACnet capture yields
# millions of them. Protocol-aware decoders claim the traffic they understand; this list
# suppresses raw carving for the rest.
TELEMETRY_UDP_PORTS = frozenset({
    67, 68,                # DHCP
    123,                   # NTP
    137, 138,              # NetBIOS name / datagram
    161, 162,              # SNMP + traps
    514,                   # syslog
    1900,                  # SSDP
    3671,                  # KNXnet/IP
    5353,                  # mDNS
    5355,                  # LLMNR
    2222,                  # EtherNet/IP implicit I/O
    20000,                 # DNP3
    34962, 34963, 34964,   # PROFINET RT
    44818,                 # EtherNet/IP explicit messaging
})

# Backstop for chatty protocols we neither decode nor list above. High enough to catch a
# short payload-bearing exchange, low enough that one flow cannot dominate the report.
MAX_RAW_UDP_CANDIDATES_PER_FLOW = 8

# Bounds the flow table itself so a port scan or address-spoofing flood cannot grow it
# without limit. Once exceeded, raw UDP carving stops and reports how much it dropped.
MAX_TRACKED_UDP_FLOWS = 200000

MIN_RAW_UDP_PAYLOAD = 32


class RawStreamDecoder:
    def __init__(
        self,
        max_udp_candidates_per_flow: int = MAX_RAW_UDP_CANDIDATES_PER_FLOW,
        max_tracked_udp_flows: int = MAX_TRACKED_UDP_FLOWS,
    ):
        self.max_udp_candidates_per_flow = max_udp_candidates_per_flow
        self.max_tracked_udp_flows = max_tracked_udp_flows
        self.udp_flow_counts: Dict[FlowKey, int] = {}
        self.suppressed_udp_packets: Counter = Counter()

    def parse_stream(self, stream: TcpStream) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []

        if stream.client_to_server and len(stream.client_to_server) >= 16:
            extracted.append({
                "data": stream.client_to_server,
                "filename": f"raw_tcp_{stream.flow.src_ip}_{stream.flow.src_port}_to_{stream.flow.dst_port}.bin",
                "source_protocol": "RAW_TCP",
                "flow": stream.flow,
                "timestamp": stream.start_time,
                "metadata": {
                    "direction": "client_to_server",
                    "packets_count": stream.packets_count,
                },
            })

        if stream.server_to_client and len(stream.server_to_client) >= 16:
            extracted.append({
                "data": stream.server_to_client,
                "filename": f"raw_tcp_{stream.flow.dst_ip}_{stream.flow.dst_port}_to_{stream.flow.src_port}.bin",
                "source_protocol": "RAW_TCP",
                "flow": stream.flow.reverse(),
                "timestamp": stream.start_time,
                "metadata": {
                    "direction": "server_to_client",
                    "packets_count": stream.packets_count,
                },
            })

        return extracted

    def parse_udp_packet(self, packet: Packet) -> List[Dict[str, Any]]:
        if packet.transport_proto != "UDP" or len(packet.payload) < MIN_RAW_UDP_PAYLOAD:
            return []

        reason = self._suppression_reason(packet)
        if reason:
            self.suppressed_udp_packets[reason] += 1
            return []

        return [{
            "data": packet.payload,
            "filename": f"raw_udp_{packet.src_ip}_{packet.src_port}.bin",
            "source_protocol": "RAW_UDP",
            "flow": packet.flow_key,
            "timestamp": packet.timestamp,
            "metadata": {
                "frame_number": packet.frame_number,
            },
        }]

    def _suppression_reason(self, packet: Packet) -> Optional[str]:
        if packet.src_port in TELEMETRY_UDP_PORTS or packet.dst_port in TELEMETRY_UDP_PORTS:
            return "telemetry_port"

        flow = packet.flow_key
        if flow is None:
            return None
        flow = flow.normalized()

        seen = self.udp_flow_counts.get(flow)
        if seen is None:
            if len(self.udp_flow_counts) >= self.max_tracked_udp_flows:
                return "flow_table_full"
            self.udp_flow_counts[flow] = 1
            return None

        if seen >= self.max_udp_candidates_per_flow:
            return "per_flow_cap"

        self.udp_flow_counts[flow] = seen + 1
        return None

    def suppression_summary(self) -> Dict[str, Any]:
        total = sum(self.suppressed_udp_packets.values())
        return {
            "raw_udp_packets_suppressed": total,
            "by_reason": dict(self.suppressed_udp_packets),
            "tracked_udp_flows": len(self.udp_flow_counts),
            "max_candidates_per_flow": self.max_udp_candidates_per_flow,
        }
