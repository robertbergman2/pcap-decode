from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str = "TCP"

    def reverse(self) -> "FlowKey":
        return FlowKey(
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
            proto=self.proto,
        )

    def normalized(self) -> "FlowKey":
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return self
        return self.reverse()

    def __str__(self) -> str:
        return f"{self.proto} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


@dataclass
class Packet:
    frame_number: int
    timestamp: float
    link_type: int
    raw_data: bytes
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_proto: Optional[int] = None
    ip_id: Optional[int] = None
    ip_frag_offset: int = 0
    ip_more_frags: bool = False
    transport_proto: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    seq_num: Optional[int] = None
    ack_num: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    payload: bytes = b""

    @property
    def flow_key(self) -> Optional[FlowKey]:
        if self.src_ip and self.dst_ip and self.src_port is not None and self.dst_port is not None:
            return FlowKey(
                src_ip=self.src_ip,
                src_port=self.src_port,
                dst_ip=self.dst_ip,
                dst_port=self.dst_port,
                proto=self.transport_proto or "UNKNOWN",
            )
        return None


@dataclass
class StreamSegment:
    timestamp: float
    frame_number: int
    seq: int
    data: bytes


@dataclass
class TcpStream:
    flow: FlowKey
    start_time: float
    end_time: float
    client_to_server: bytes = b""
    server_to_client: bytes = b""
    client_segments: List[StreamSegment] = field(default_factory=list)
    server_segments: List[StreamSegment] = field(default_factory=list)
    packets_count: int = 0
    is_closed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


def serialize_obj(val: Any) -> Any:
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return val.to_dict()
    elif isinstance(val, dict):
        return {k: serialize_obj(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [serialize_obj(item) for item in val]
    return val


@dataclass
class ExtractedFile:
    file_id: str
    filename: str
    data: bytes
    size: int
    md5: str
    sha1: str
    sha256: str
    entropy: float
    source_protocol: str
    flow: Optional[FlowKey] = None
    timestamp: float = 0.0
    magic_type: str = "Unknown Binary Data"
    extension: str = "bin"
    metadata: Dict[str, Any] = field(default_factory=dict)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    threat_level: ThreatLevel = ThreatLevel.INFO

    def to_dict(self, include_data: bool = False) -> Dict[str, Any]:
        result = {
            "file_id": self.file_id,
            "filename": self.filename,
            "extension": self.extension,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 3),
            "magic_type": self.magic_type,
            "source_protocol": self.source_protocol,
            "timestamp": self.timestamp,
            "flow": str(self.flow) if self.flow else None,
            "src_ip": self.flow.src_ip if self.flow else None,
            "src_port": self.flow.src_port if self.flow else None,
            "dst_ip": self.flow.dst_ip if self.flow else None,
            "dst_port": self.flow.dst_port if self.flow else None,
            "threat_level": self.threat_level.value,
            "threat_score": self.threat_score,
            "threat_indicators": self.threat_indicators,
            "metadata": serialize_obj(self.metadata),
        }
        if include_data:
            result["data_hex"] = self.data.hex()
        return result
