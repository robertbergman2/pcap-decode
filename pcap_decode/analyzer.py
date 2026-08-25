import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from pcap_decode.models import ExtractedFile, FlowKey, ThreatLevel
from pcap_decode.pe_parser import PeInfo, parse_pe


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


def detect_file_type(data: bytes) -> Tuple[str, str]:
    if not data:
        return "Empty File", "bin"

    if data.startswith(b"MZ"):
        pe_info = parse_pe(data)
        if pe_info and pe_info.is_pe:
            subsys = pe_info.subsystem_name
            ext = "sys" if pe_info.subsystem == 1 else "exe"
            return f"Windows PE Executable ({pe_info.machine_name}, {subsys})", ext
        return "DOS/MZ Executable Header", "exe"

    if data.startswith(b"\x7fELF"):
        return "Linux ELF Executable", "elf"

    if data.startswith(b"\xfe\xed\xfa\xce") or data.startswith(b"\xfe\xed\xfa\xcf") or data.startswith(b"\xce\xfa\xed\xfe") or data.startswith(b"\xcf\xfa\xed\xfe"):
        return "macOS Mach-O Binary", "macho"

    if data.startswith(b"\xca\xfe\xba\xbe"):
        if len(data) >= 8 and data[4:8] in (b"\x00\x00\x00\x30", b"\x00\x00\x00\x31", b"\x00\x00\x00\x32", b"\x00\x00\x00\x33", b"\x00\x00\x00\x34"):
            return "Java Class File", "class"
        return "Mach-O Fat Binary / Java Class", "bin"

    if data.startswith(b"PK\x03\x04"):
        if b"word/" in data or b"[Content_Types].xml" in data:
            return "Microsoft Office OpenXML Document (Word/Excel)", "docx"
        elif b"xl/" in data:
            return "Microsoft Excel OpenXML Workbook", "xlsx"
        elif b"ppt/" in data:
            return "Microsoft PowerPoint Presentation", "pptx"
        elif b"AndroidManifest.xml" in data:
            return "Android APK Package", "apk"
        elif b"META-INF/MANIFEST.MF" in data:
            return "Java JAR Archive", "jar"
        return "ZIP Archive", "zip"

    if data.startswith(b"%PDF-"):
        return "PDF Document", "pdf"

    if data.startswith(b"{\\rtf"):
        return "Rich Text Format (RTF) Document", "rtf"

    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "Microsoft Office Compound Document (OLE2 / Legacy DOC/XLS)", "doc"

    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip Archive", "7z"

    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR Archive", "rar"

    if data.startswith(b"\x1f\x8b\x08"):
        return "GZIP Compressed Archive", "gz"

    if data.startswith(b"BZh"):
        return "BZIP2 Compressed Archive", "bz2"

    if data.startswith(b"\xfd7zXZ\x00"):
        return "XZ Compressed Archive", "xz"

    if data.startswith(b"\x00asm"):
        return "WebAssembly Binary (WASM)", "wasm"

    lower_prefix = data[:1024].lower()
    if lower_prefix.startswith(b"#!/bin/sh") or lower_prefix.startswith(b"#!/bin/bash") or lower_prefix.startswith(b"#!/usr/bin/env bash"):
        return "Unix Shell Script", "sh"

    if lower_prefix.startswith(b"#!/usr/bin/env python") or lower_prefix.startswith(b"#!/usr/bin/python"):
        return "Python Script", "py"

    if lower_prefix.startswith(b"@echo off") or b"setlocal" in lower_prefix:
        return "Windows Batch Script", "bat"

    if b"powershell" in lower_prefix or b"invoke-expression" in lower_prefix or b"downloadstring" in lower_prefix or b"new-object net.webclient" in lower_prefix:
        return "PowerShell Script", "ps1"

    if b"wscript.shell" in lower_prefix or b"createobject(" in lower_prefix:
        return "VBScript / WSH Script", "vbs"

    if b"<!doctype html" in lower_prefix or b"<html" in lower_prefix:
        return "HTML Document", "html"

    if b"<?xml" in lower_prefix:
        return "XML Document", "xml"

    try:
        data.decode("utf-8")
        return "Plain Text / Script", "txt"
    except UnicodeDecodeError:
        pass

    return "Generic Binary Data", "bin"


class MalwareAnalyzer:
    def analyze_payload(self, raw_data: bytes, source_proto: str = "UNKNOWN", flow: Optional[FlowKey] = None, timestamp: float = 0.0, filename: str = "", metadata: Optional[Dict[str, Any]] = None) -> ExtractedFile:
        data = raw_data
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        entropy = calculate_entropy(data)
        meta = metadata or {}

        magic_type, suggested_ext = detect_file_type(data)

        clean_filename = filename or f"extracted_{sha256_hash[:12]}.{suggested_ext}"
        if "." not in clean_filename:
            clean_filename = f"{clean_filename}.{suggested_ext}"

        threat_indicators: List[str] = []
        threat_score = 0

        if meta.get("xor_key") is not None or "XOR_DEOBFUSCATION" in meta.get("carve_method", ""):
            threat_indicators.append(f"Deobfuscated payload using XOR key {meta.get('xor_key', 'unknown')}")
            threat_score += 40

        if entropy > 7.2 and len(data) > 1024:
            threat_indicators.append(f"High entropy ({entropy:.2f}/8.0) - likely packed, encrypted, or compressed payload")
            threat_score += 20
        elif entropy < 1.0 and len(data) > 256:
            threat_indicators.append(f"Extremely low entropy ({entropy:.2f}/8.0) - repetitive payload or NOP sled")
            threat_score += 10

        if "PE Executable" in magic_type or data.startswith(b"MZ"):
            pe_info = meta.get("pe_info") or parse_pe(data)
            if pe_info and pe_info.is_pe:
                threat_score += 15
                threat_indicators.append(f"Executable binary transfer: {pe_info.machine_name} ({pe_info.subsystem_name})")
                
                suspicious_sections = {"upx0", "upx1", "upx2", ".vmp0", ".vmp1", "themida", ".aspack", ".ndata", ".packer", ".mpress"}
                for sec in pe_info.sections:
                    sec_name = sec["name"].lower().strip()
                    if sec_name in suspicious_sections:
                        threat_indicators.append(f"Known packer/protector section detected: {sec['name']}")
                        threat_score += 30

                suspicious_apis = [
                    (b"VirtualAlloc", "VirtualAlloc (Memory Allocation for Shellcode/Payload)"),
                    (b"VirtualProtect", "VirtualProtect (Memory Permission Modification)"),
                    (b"WriteProcessMemory", "WriteProcessMemory (Process Injection)"),
                    (b"CreateRemoteThread", "CreateRemoteThread (Remote Thread Injection)"),
                    (b"NtQueueApcThread", "NtQueueApcThread (Early Bird / APC Injection)"),
                    (b"SetThreadContext", "SetThreadContext (Thread Hijacking)"),
                    (b"NtUnmapViewOfSection", "NtUnmapViewOfSection (Process Hollowing)"),
                    (b"IsDebuggerPresent", "IsDebuggerPresent (Anti-Debugging)"),
                    (b"CheckRemoteDebuggerPresent", "CheckRemoteDebuggerPresent (Anti-Debugging)"),
                    (b"URLDownloadToFile", "URLDownloadToFile (Malware Downloader)"),
                    (b"InternetOpen", "InternetOpen (WinINet C2 Communication)"),
                    (b"HttpSendRequest", "HttpSendRequest (HTTP C2 Beaconing)"),
                    (b"AdjustTokenPrivileges", "AdjustTokenPrivileges (Privilege Escalation)"),
                    (b"CryptEncrypt", "CryptEncrypt (Encryption / Ransomware)"),
                ]
                
                found_apis = []
                for api_bytes, api_desc in suspicious_apis:
                    if api_bytes in data:
                        found_apis.append(api_desc)
                        threat_score += 10

                if found_apis:
                    threat_indicators.append(f"Suspicious API references ({len(found_apis)}): " + ", ".join(found_apis[:5]))

        if "PDF" in magic_type:
            pdf_alerts = []
            for tag in (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFiles", b"/OpenAction", b"/AcroForm"):
                if tag in data:
                    pdf_alerts.append(tag.decode("latin1"))
                    threat_score += 15
            if pdf_alerts:
                threat_indicators.append("Suspicious PDF active elements: " + ", ".join(pdf_alerts))

        if "Office" in magic_type or "OLE2" in magic_type:
            doc_alerts = []
            for kw in (b"AutoOpen", b"Workbook_Open", b"Document_Open", b"VBA", b"ExecuteExcel4Macro", b"Shell", b"WScript"):
                if kw in data:
                    doc_alerts.append(kw.decode("latin1"))
                    threat_score += 20
            if doc_alerts:
                threat_indicators.append("Suspicious Office macro/automation keywords: " + ", ".join(doc_alerts))

        if suggested_ext in ("ps1", "sh", "bat", "vbs", "py", "txt"):
            script_alerts = []
            script_patterns = [
                (rb"(?i)downloadstring|downloaddata|downloadfile", "WebClient Download Execution"),
                (rb"(?i)invoke-expression|iex\b", "Invoke-Expression (In-Memory Execution)"),
                (rb"(?i)-encodedcommand|-enc\b", "PowerShell Encoded Command"),
                (rb"(?i)bypass\s+-noprofile", "PowerShell Execution Policy Bypass"),
                (rb"(?i)invoke-mimikatz", "Mimikatz Credential Dumping"),
                (rb"(?i)frombase64string", "Base64 Decoding Routine"),
                (rb"(?i)wscript\.shell", "WSH Shell Execution"),
                (rb"(?i)cmd\.exe\s+/c|powershell\.exe", "Command Interpreter Spawn"),
                (rb"(?i)curl\s+.*\s+\|\s+(?:bash|sh)|wget\s+.*\s+\|\s+(?:bash|sh)", "Remote Script Piping (curl | sh)"),
                (rb"(?i)nc\s+-[e|c]|ncat\s+-e|/bin/sh\s+-i|/bin/bash\s+-i", "Reverse Shell Command"),
            ]
            for pat, desc in script_patterns:
                if re.search(pat, data):
                    script_alerts.append(desc)
                    threat_score += 25
            if script_alerts:
                threat_indicators.append("Script threat indicators: " + ", ".join(script_alerts))

        if b"\x90" * 32 in data or b"\xcc" * 32 in data:
            threat_indicators.append("Detected potential NOP sled or INT3 padding (>=32 consecutive bytes)")
            threat_score += 20

        iocs = self._extract_iocs(data)
        if iocs["urls"]:
            meta["embedded_urls"] = iocs["urls"][:10]
            threat_indicators.append(f"Embedded URLs found ({len(iocs['urls'])}): " + ", ".join(iocs["urls"][:3]))
            threat_score += 10
        if iocs["ips"]:
            meta["embedded_ips"] = iocs["ips"][:10]

        threat_score = min(100, threat_score)

        if threat_score >= 70:
            threat_level = ThreatLevel.CRITICAL
        elif threat_score >= 45:
            threat_level = ThreatLevel.HIGH
        elif threat_score >= 25:
            threat_level = ThreatLevel.MEDIUM
        elif threat_score >= 10:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.INFO

        return ExtractedFile(
            file_id=sha256_hash[:16],
            filename=clean_filename,
            data=data,
            size=len(data),
            md5=md5_hash,
            sha1=sha1_hash,
            sha256=sha256_hash,
            entropy=entropy,
            source_protocol=source_proto,
            flow=flow,
            timestamp=timestamp,
            magic_type=magic_type,
            extension=suggested_ext,
            metadata=meta,
            threat_indicators=threat_indicators,
            threat_score=threat_score,
            threat_level=threat_level,
        )

    def _extract_iocs(self, data: bytes) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {"urls": [], "ips": [], "domains": []}
        try:
            text = data.decode("latin1", errors="ignore")
        except Exception:
            return results

        url_matches = re.findall(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+", text)
        if url_matches:
            results["urls"] = list(dict.fromkeys(url_matches))

        ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        valid_ips = []
        for ip in ip_matches:
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets) and not ip.startswith("0.") and ip != "255.255.255.255":
                valid_ips.append(ip)
        if valid_ips:
            results["ips"] = list(dict.fromkeys(valid_ips))

        return results
