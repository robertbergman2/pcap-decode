from typing import Any, Dict, List

from pcap_decode.models import FlowKey, Packet, TcpStream


class RawStreamDecoder:
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
        extracted: List[Dict[str, Any]] = []
        if packet.transport_proto == "UDP" and len(packet.payload) >= 32:
            extracted.append({
                "data": packet.payload,
                "filename": f"raw_udp_{packet.src_ip}_{packet.src_port}.bin",
                "source_protocol": "RAW_UDP",
                "flow": packet.flow_key,
                "timestamp": packet.timestamp,
                "metadata": {
                    "frame_number": packet.frame_number,
                },
            })
        return extracted
