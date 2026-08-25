import struct
from typing import Any, Dict, List, Optional, Tuple


class PeInfo:
    def __init__(self):
        self.is_pe = False
        self.is_64bit = False
        self.machine = 0
        self.machine_name = "Unknown"
        self.subsystem = 0
        self.subsystem_name = "Unknown"
        self.timestamp = 0
        self.entry_point = 0
        self.image_base = 0
        self.sections_count = 0
        self.calculated_size = 0
        self.sections: List[Dict[str, Any]] = []
        self.imported_functions: List[str] = []
        self.imported_dlls: List[str] = []
        self.exported_functions: List[str] = []
        self.has_overlay = False
        self.overlay_size = 0
        self.is_dotnet = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_pe": self.is_pe,
            "is_64bit": self.is_64bit,
            "machine": self.machine,
            "machine_name": self.machine_name,
            "subsystem": self.subsystem,
            "subsystem_name": self.subsystem_name,
            "timestamp": self.timestamp,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "sections_count": self.sections_count,
            "calculated_size": self.calculated_size,
            "sections": self.sections,
            "imported_functions": self.imported_functions,
            "imported_dlls": self.imported_dlls,
            "exported_functions": self.exported_functions,
            "has_overlay": self.has_overlay,
            "overlay_size": self.overlay_size,
            "is_dotnet": self.is_dotnet,
        }


def parse_pe(data: bytes) -> Optional[PeInfo]:
    if len(data) < 64:
        return None
    if data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack("<I", data[60:64])[0]
    if e_lfanew + 24 > len(data):
        return None

    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    info = PeInfo()
    info.is_pe = True

    coff_offset = e_lfanew + 4
    machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack(
        "<HHIIIHH", data[coff_offset:coff_offset + 20]
    )

    info.machine = machine
    info.timestamp = timedatestamp
    info.sections_count = num_sections

    if machine == 0x014C:
        info.machine_name = "x86 (32-bit)"
    elif machine == 0x8664:
        info.machine_name = "x64 (64-bit AMD64)"
    elif machine == 0xAA64:
        info.machine_name = "ARM64"
    elif machine == 0x01C0:
        info.machine_name = "ARM"

    opt_offset = coff_offset + 20
    if opt_hdr_size > 0 and opt_offset + opt_hdr_size <= len(data):
        opt_magic = struct.unpack("<H", data[opt_offset:opt_offset + 2])[0]
        if opt_magic == 0x10B:
            info.is_64bit = False
            if opt_offset + 68 <= len(data):
                info.entry_point = struct.unpack("<I", data[opt_offset + 16:opt_offset + 20])[0]
                info.image_base = struct.unpack("<I", data[opt_offset + 28:opt_offset + 32])[0]
                info.subsystem = struct.unpack("<H", data[opt_offset + 68:opt_offset + 70])[0]
        elif opt_magic == 0x20B:
            info.is_64bit = True
            if opt_offset + 68 <= len(data):
                info.entry_point = struct.unpack("<I", data[opt_offset + 16:opt_offset + 20])[0]
                info.image_base = struct.unpack("<Q", data[opt_offset + 24:opt_offset + 32])[0]
                info.subsystem = struct.unpack("<H", data[opt_offset + 68:opt_offset + 70])[0]

        subsystems = {
            1: "Native / Driver",
            2: "Windows GUI",
            3: "Windows Console / CLI",
            7: "POSIX",
            9: "Windows CE",
            10: "EFI Application",
        }
        info.subsystem_name = subsystems.get(info.subsystem, f"Other ({info.subsystem})")

    sections_start = opt_offset + opt_hdr_size
    max_raw_end = sections_start

    for i in range(num_sections):
        sec_hdr_offset = sections_start + (i * 40)
        if sec_hdr_offset + 40 > len(data):
            break
        
        sec_name = data[sec_hdr_offset:sec_hdr_offset + 8].rstrip(b"\x00").decode("latin1", errors="replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack("<IIII", data[sec_hdr_offset + 8:sec_hdr_offset + 24])
        
        sec_end = raw_ptr + raw_size
        if sec_end > max_raw_end:
            max_raw_end = sec_end

        info.sections.append({
            "name": sec_name,
            "virtual_size": vsize,
            "virtual_address": vaddr,
            "raw_size": raw_size,
            "raw_offset": raw_ptr,
        })

    security_dir_offset = opt_offset + (128 if not info.is_64bit else 144)
    if security_dir_offset + 8 <= len(data):
        cert_va, cert_size = struct.unpack("<II", data[security_dir_offset:security_dir_offset + 8])
        if cert_va > 0 and cert_size > 0:
            cert_end = cert_va + cert_size
            if cert_end > max_raw_end:
                max_raw_end = cert_end

    info.calculated_size = min(len(data), max_raw_end) if max_raw_end > 0 else len(data)
    if len(data) > info.calculated_size:
        info.has_overlay = True
        info.overlay_size = len(data) - info.calculated_size

    return info
