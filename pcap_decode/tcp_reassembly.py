from collections import defaultdict
from typing import Dict, Generator, List, Optional, Tuple

from pcap_decode.models import FlowKey, Packet, StreamSegment, TcpStream


def seq_diff(seq1: int, seq2: int) -> int:
    diff = (seq1 - seq2) & 0xFFFFFFFF
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


class DirectionalReassembler:
    def __init__(self):
        self.base_seq: Optional[int] = None
        self.next_expected_seq: Optional[int] = None
        self.data_buffer = bytearray()
        self.segments: List[StreamSegment] = []
        self.out_of_order: List[Tuple[int, bytes, float, int]] = []
        self.is_closed = False

    def add_segment(self, seq: int, data: bytes, flags: dict, timestamp: float, frame_num: int):
        has_syn = flags.get("SYN", False)
        has_fin = flags.get("FIN", False)
        has_rst = flags.get("RST", False)

        if has_rst:
            self.is_closed = True

        if has_syn:
            self.base_seq = (seq + 1) & 0xFFFFFFFF
            self.next_expected_seq = self.base_seq
            if not data:
                return

        if not data:
            if has_fin:
                self.is_closed = True
            return

        if self.base_seq is None:
            self.base_seq = seq
            self.next_expected_seq = (seq + len(data)) & 0xFFFFFFFF
            self.data_buffer.extend(data)
            self.segments.append(StreamSegment(timestamp=timestamp, frame_number=frame_num, seq=seq, data=data))
            return

        if seq_diff(seq, self.base_seq) < 0:
            diff_to_base = seq_diff(self.base_seq, seq)
            if diff_to_base > 0:
                prepend_len = min(diff_to_base, len(data))
                prepend_data = data[:prepend_len]
                self.data_buffer = bytearray(prepend_data) + self.data_buffer
                self.base_seq = seq
                self.segments.insert(0, StreamSegment(timestamp=timestamp, frame_number=frame_num, seq=seq, data=prepend_data))
                if len(data) > prepend_len:
                    rem_data = data[prepend_len:]
                    rem_seq = (seq + prepend_len) & 0xFFFFFFFF
                    self.add_segment(rem_seq, rem_data, flags, timestamp, frame_num)
                return

        expected = self.next_expected_seq

        if seq == expected:
            self._append_data(data, timestamp, frame_num, seq)
            self._process_out_of_order()
        elif seq_diff(seq, expected) < 0:
            overlap = seq_diff(expected, seq)
            if overlap < len(data):
                new_data = data[overlap:]
                new_seq = (seq + overlap) & 0xFFFFFFFF
                self._append_data(new_data, timestamp, frame_num, new_seq)
                self._process_out_of_order()
        else:
            self.out_of_order.append((seq, data, timestamp, frame_num))
            self.out_of_order.sort(key=lambda item: item[0])
            self._process_out_of_order()

        if has_fin:
            self.is_closed = True

    def _append_data(self, data: bytes, timestamp: float, frame_num: int, seq: int):
        self.data_buffer.extend(data)
        self.segments.append(StreamSegment(timestamp=timestamp, frame_number=frame_num, seq=seq, data=data))
        self.next_expected_seq = (self.next_expected_seq + len(data)) & 0xFFFFFFFF

    def _process_out_of_order(self):
        progress = True
        while progress and self.out_of_order:
            progress = False
            remaining = []
            for seq, data, ts, frame_num in self.out_of_order:
                diff = seq_diff(seq, self.next_expected_seq)
                if diff <= 0:
                    overlap = -diff
                    if overlap < len(data):
                        new_data = data[overlap:]
                        new_seq = (seq + overlap) & 0xFFFFFFFF
                        self._append_data(new_data, ts, frame_num, new_seq)
                        progress = True
                else:
                    remaining.append((seq, data, ts, frame_num))
            self.out_of_order = remaining

    def get_data(self) -> bytes:
        if self.out_of_order and len(self.data_buffer) == 0:
            sorted_frags = sorted(self.out_of_order, key=lambda x: x[0])
            fallback = bytearray()
            for _, d, _, _ in sorted_frags:
                fallback.extend(d)
            return bytes(fallback)
        return bytes(self.data_buffer)


class ConnectionTracker:
    def __init__(self, client_flow: FlowKey, start_time: float):
        self.client_flow = client_flow
        self.start_time = start_time
        self.end_time = start_time
        self.packets_count = 0
        self.client_to_server = DirectionalReassembler()
        self.server_to_client = DirectionalReassembler()
        self.is_closed = False

    def process_packet(self, packet: Packet):
        self.packets_count += 1
        self.end_time = max(self.end_time, packet.timestamp)
        flags = packet.tcp_flags or {}
        
        is_c2s = (packet.src_ip == self.client_flow.src_ip and packet.src_port == self.client_flow.src_port)
        if is_c2s:
            self.client_to_server.add_segment(
                packet.seq_num or 0,
                packet.payload,
                flags,
                packet.timestamp,
                packet.frame_number,
            )
        else:
            self.server_to_client.add_segment(
                packet.seq_num or 0,
                packet.payload,
                flags,
                packet.timestamp,
                packet.frame_number,
            )

        if (self.client_to_server.is_closed and self.server_to_client.is_closed) or flags.get("RST", False):
            self.is_closed = True

    def build_stream(self) -> TcpStream:
        return TcpStream(
            flow=self.client_flow,
            start_time=self.start_time,
            end_time=self.end_time,
            client_to_server=self.client_to_server.get_data(),
            server_to_client=self.server_to_client.get_data(),
            client_segments=self.client_to_server.segments,
            server_segments=self.server_to_client.segments,
            packets_count=self.packets_count,
            is_closed=self.is_closed,
        )


class TcpReassembler:
    def __init__(self):
        self.connections: Dict[FlowKey, ConnectionTracker] = {}

    def process_packet(self, packet: Packet) -> Optional[TcpStream]:
        if packet.transport_proto != "TCP" or not packet.flow_key:
            return None

        flow = packet.flow_key
        norm_flow = flow.normalized()

        if norm_flow not in self.connections:
            tracker_flow = flow
            if packet.tcp_flags and not packet.tcp_flags.get("SYN", False) and norm_flow != flow:
                tracker_flow = norm_flow
            self.connections[norm_flow] = ConnectionTracker(tracker_flow, packet.timestamp)

        tracker = self.connections[norm_flow]
        tracker.process_packet(packet)

        if tracker.is_closed and (len(tracker.client_to_server.data_buffer) > 0 or len(tracker.server_to_client.data_buffer) > 0):
            stream = tracker.build_stream()
            del self.connections[norm_flow]
            return stream

        return None

    def finalize(self) -> Generator[TcpStream, None, None]:
        for norm_flow, tracker in list(self.connections.items()):
            if tracker.packets_count > 0:
                yield tracker.build_stream()
        self.connections.clear()
