from pcap_decode.analyzer import MalwareAnalyzer
from pcap_decode.carver import FileCarver
from pcap_decode.engine import PcapDecoderEngine
from pcap_decode.exporter import Exporter
from pcap_decode.models import ExtractedFile, FlowKey, Packet, TcpStream, ThreatLevel
from pcap_decode.pcap_reader import PcapReader


def analyze_pcap(pcap_path: str, output_dir: str = "extracted_payloads", carve_raw: bool = True) -> dict:
    engine = PcapDecoderEngine(carve_raw_streams=carve_raw)
    result = engine.decode_file(pcap_path)
    exporter = Exporter(output_dir=output_dir)
    return exporter.export(result)


__all__ = [
    "PcapReader",
    "PcapDecoderEngine",
    "FileCarver",
    "MalwareAnalyzer",
    "Exporter",
    "Packet",
    "TcpStream",
    "FlowKey",
    "ExtractedFile",
    "ThreatLevel",
    "analyze_pcap",
]
