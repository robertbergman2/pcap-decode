import os
import time
from typing import Any, Dict, List, Optional, Set, Union

from pcap_decode.analyzer import MalwareAnalyzer
from pcap_decode.carver import FileCarver
from pcap_decode.ip_reassembly import IpDefragmenter
from pcap_decode.models import ExtractedFile, Packet, TcpStream, ThreatLevel
from pcap_decode.pcap_reader import PcapReader
from pcap_decode.protocols.dns import DnsDecoder
from pcap_decode.protocols.email import EmailDecoder
from pcap_decode.protocols.ftp import FtpDecoder
from pcap_decode.protocols.http import HttpDecoder
from pcap_decode.protocols.raw import RawStreamDecoder
from pcap_decode.protocols.smb import SmbDecoder
from pcap_decode.tcp_reassembly import TcpReassembler


class PcapDecoderEngine:
    def __init__(self, carve_raw_streams: bool = True, min_payload_size: int = 16):
        self.carve_raw_streams = carve_raw_streams
        self.min_payload_size = min_payload_size
        self.ip_defrag = IpDefragmenter()
        self.tcp_reassembler = TcpReassembler()
        self.http_decoder = HttpDecoder()
        self.email_decoder = EmailDecoder()
        self.ftp_decoder = FtpDecoder()
        self.smb_decoder = SmbDecoder()
        self.dns_decoder = DnsDecoder()
        self.raw_decoder = RawStreamDecoder()
        self.carver = FileCarver()
        self.analyzer = MalwareAnalyzer()

    def decode_file(self, pcap_path: str) -> Dict[str, Any]:
        start_time = time.time()
        packets_count = 0
        tcp_streams_count = 0
        udp_packets_count = 0
        raw_candidates: List[Dict[str, Any]] = []

        with PcapReader(pcap_path) as reader:
            for raw_pkt in reader.packets():
                packets_count += 1
                pkt = self.ip_defrag.process(raw_pkt)
                if not pkt:
                    continue

                if pkt.transport_proto == "UDP":
                    udp_packets_count += 1
                    dns_objs = self.dns_decoder.process_packet(pkt)
                    if dns_objs:
                        raw_candidates.extend(dns_objs)
                    if self.carve_raw_streams and len(pkt.payload) >= 32:
                        raw_candidates.extend(self.raw_decoder.parse_udp_packet(pkt))

                elif pkt.transport_proto == "TCP":
                    stream = self.tcp_reassembler.process_packet(pkt)
                    if stream:
                        tcp_streams_count += 1
                        self._process_stream(stream, raw_candidates)

            for stream in self.tcp_reassembler.finalize():
                tcp_streams_count += 1
                self._process_stream(stream, raw_candidates)

        extracted_files = self._analyze_and_deduplicate(raw_candidates)

        elapsed = time.time() - start_time
        return {
            "pcap_path": os.path.abspath(pcap_path),
            "packets_count": packets_count,
            "tcp_streams_count": tcp_streams_count,
            "udp_packets_count": udp_packets_count,
            "extracted_files_count": len(extracted_files),
            "extracted_files": extracted_files,
            "suspicious_domains": self.dns_decoder.suspicious_domains,
            "processing_time_seconds": round(elapsed, 4),
            "threat_summary": self._compute_threat_summary(extracted_files),
        }

    def _process_stream(self, stream: TcpStream, candidates: List[Dict[str, Any]]):
        has_protocol_match = False

        http_objs = self.http_decoder.parse_stream(stream)
        if http_objs:
            has_protocol_match = True
            candidates.extend(http_objs)

        email_objs = self.email_decoder.parse_stream(stream)
        if email_objs:
            has_protocol_match = True
            candidates.extend(email_objs)

        ftp_objs = self.ftp_decoder.parse_stream(stream)
        if ftp_objs:
            has_protocol_match = True
            candidates.extend(ftp_objs)

        smb_objs = self.smb_decoder.parse_stream(stream)
        if smb_objs:
            has_protocol_match = True
            candidates.extend(smb_objs)

        for data_chunk, direction in [(stream.client_to_server, "c2s"), (stream.server_to_client, "s2c")]:
            if len(data_chunk) >= self.min_payload_size:
                carved_items = self.carver.carve_all(data_chunk)
                for item in carved_items:
                    flow_obj = stream.flow if direction == "c2s" else stream.flow.reverse()
                    candidates.append({
                        "data": item["data"],
                        "filename": item.get("filename", "carved_payload.bin"),
                        "source_protocol": f"CARVED_{item.get('carve_method', 'SIG')}",
                        "flow": flow_obj,
                        "timestamp": stream.start_time,
                        "metadata": {
                            "carve_offset": item.get("carve_offset", 0),
                            "carve_method": item.get("carve_method", ""),
                            "xor_key": item.get("xor_key"),
                            "pe_info": item.get("pe_info"),
                            "stream_direction": direction,
                        },
                    })

        if not has_protocol_match and self.carve_raw_streams:
            candidates.extend(self.raw_decoder.parse_stream(stream))

    def _analyze_and_deduplicate(self, raw_candidates: List[Dict[str, Any]]) -> List[ExtractedFile]:
        seen_hashes: Dict[str, ExtractedFile] = {}

        for item in raw_candidates:
            data = item.get("data", b"")
            if not data or len(data) < self.min_payload_size:
                continue

            analyzed = self.analyzer.analyze_payload(
                raw_data=data,
                source_proto=item.get("source_protocol", "UNKNOWN"),
                flow=item.get("flow"),
                timestamp=item.get("timestamp", 0.0),
                filename=item.get("filename", ""),
                metadata=item.get("metadata", {}),
            )

            if analyzed.sha256 in seen_hashes:
                existing = seen_hashes[analyzed.sha256]
                if analyzed.threat_score > existing.threat_score:
                    existing.threat_score = analyzed.threat_score
                    existing.threat_level = analyzed.threat_level
                for ind in analyzed.threat_indicators:
                    if ind not in existing.threat_indicators:
                        existing.threat_indicators.append(ind)
                if not existing.filename.endswith(analyzed.extension) and analyzed.extension != "bin":
                    existing.filename = analyzed.filename
                    existing.extension = analyzed.extension
                    existing.magic_type = analyzed.magic_type
            else:
                seen_hashes[analyzed.sha256] = analyzed

        results = list(seen_hashes.values())
        results.sort(key=lambda x: (x.threat_score, x.size), reverse=True)
        return results

    def _compute_threat_summary(self, files: List[ExtractedFile]) -> Dict[str, int]:
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "total_files": len(files),
        }
        for f in files:
            summary[f.threat_level.value] += 1
        return summary
