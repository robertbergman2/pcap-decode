import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from pcap_decode.pe_parser import parse_pe


def calculate_elf_size(data: bytes) -> int:
    if len(data) < 52:
        return len(data)
    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == 1 else ">"

    if ei_class == 1:
        if len(data) < 52:
            return len(data)
        e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, _ = struct.unpack(
            f"{endian}IIIHHHHHH", data[28:52]
        )
        end1 = e_phoff + (e_phnum * e_phentsize) if e_phoff > 0 else 0
        end2 = e_shoff + (e_shnum * e_shentsize) if e_shoff > 0 else 0
        return min(len(data), max(end1, end2, 52))
    elif ei_class == 2:
        if len(data) < 64:
            return len(data)
        e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, _ = struct.unpack(
            f"{endian}QQIHHHHHH", data[32:64]
        )
        end1 = e_phoff + (e_phnum * e_phentsize) if e_phoff > 0 else 0
        end2 = e_shoff + (e_shnum * e_shentsize) if e_shoff > 0 else 0
        return min(len(data), max(end1, end2, 64))

    return len(data)


def calculate_zip_size(data: bytes) -> int:
    eocd_sig = b"PK\x05\x06"
    eocd_pos = data.rfind(eocd_sig)
    if eocd_pos != -1 and len(data) >= eocd_pos + 22:
        comment_len = struct.unpack("<H", data[eocd_pos + 20:eocd_pos + 22])[0]
        return min(len(data), eocd_pos + 22 + comment_len)
    return len(data)


def calculate_pdf_size(data: bytes) -> int:
    eof_sig = b"%%EOF"
    pos = data.rfind(eof_sig)
    if pos != -1:
        end = pos + len(eof_sig)
        while end < len(data) and data[end:end+1] in (b"\r", b"\n", b" ", b"\t"):
            end += 1
        return end
    return len(data)


class FileCarver:
    def carve_all(self, data: bytes) -> List[Dict[str, Any]]:
        if not data or len(data) < 16:
            return []

        results: List[Dict[str, Any]] = []

        direct_carved = self._carve_signatures(data)
        results.extend(direct_carved)

        xor_carved = self._carve_xor_pe(data)
        results.extend(xor_carved)

        script_carved = self._carve_scripts(data)
        results.extend(script_carved)

        return results

    def _carve_signatures(self, data: bytes) -> List[Dict[str, Any]]:
        extracted = []
        data_len = len(data)

        mz_indices = [m.start() for m in re.finditer(b"MZ", data)]
        for idx in mz_indices:
            candidate = data[idx:]
            pe_info = parse_pe(candidate)
            if pe_info and pe_info.is_pe:
                exact_size = pe_info.calculated_size
                pe_bytes = candidate[:exact_size]
                if len(pe_bytes) >= 512:
                    extracted.append({
                        "data": pe_bytes,
                        "filename": f"carved_pe_{idx}.exe",
                        "extension": "exe" if pe_info.subsystem != 1 else "sys",
                        "magic_type": f"Windows PE Executable ({pe_info.machine_name}, {pe_info.subsystem_name})",
                        "carve_offset": idx,
                        "carve_method": "PE_SIGNATURE",
                        "pe_info": pe_info,
                    })

        elf_indices = [m.start() for m in re.finditer(b"\x7fELF", data)]
        for idx in elf_indices:
            candidate = data[idx:]
            if len(candidate) >= 52:
                exact_size = calculate_elf_size(candidate)
                elf_bytes = candidate[:exact_size]
                if len(elf_bytes) >= 52:
                    extracted.append({
                        "data": elf_bytes,
                        "filename": f"carved_elf_{idx}.elf",
                        "extension": "elf",
                        "magic_type": "ELF Executable / Shared Object",
                        "carve_offset": idx,
                        "carve_method": "ELF_SIGNATURE",
                    })

        macho_sigs = [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"]
        for sig in macho_sigs:
            for m in re.finditer(re.escape(sig), data):
                idx = m.start()
                extracted.append({
                    "data": data[idx:],
                    "filename": f"carved_macho_{idx}.macho",
                    "extension": "macho",
                    "magic_type": "Mach-O Binary",
                    "carve_offset": idx,
                    "carve_method": "MACHO_SIGNATURE",
                })

        zip_indices = [m.start() for m in re.finditer(b"PK\x03\x04", data)]
        for idx in zip_indices:
            candidate = data[idx:]
            exact_size = calculate_zip_size(candidate)
            zip_bytes = candidate[:exact_size]
            if len(zip_bytes) >= 30:
                is_docx = b"word/" in zip_bytes or b"[Content_Types].xml" in zip_bytes
                is_jar = b"META-INF/MANIFEST.MF" in zip_bytes
                is_apk = b"AndroidManifest.xml" in zip_bytes
                ext = "docx" if is_docx else ("apk" if is_apk else ("jar" if is_jar else "zip"))
                mtype = "Office OpenXML Document" if is_docx else ("Android APK" if is_apk else ("Java JAR Archive" if is_jar else "ZIP Archive"))
                extracted.append({
                    "data": zip_bytes,
                    "filename": f"carved_archive_{idx}.{ext}",
                    "extension": ext,
                    "magic_type": mtype,
                    "carve_offset": idx,
                    "carve_method": "ZIP_SIGNATURE",
                })

        pdf_indices = [m.start() for m in re.finditer(b"%PDF-", data)]
        for idx in pdf_indices:
            candidate = data[idx:]
            exact_size = calculate_pdf_size(candidate)
            pdf_bytes = candidate[:exact_size]
            if len(pdf_bytes) >= 32:
                extracted.append({
                    "data": pdf_bytes,
                    "filename": f"carved_document_{idx}.pdf",
                    "extension": "pdf",
                    "magic_type": "PDF Document",
                    "carve_offset": idx,
                    "carve_method": "PDF_SIGNATURE",
                })

        ole_sig = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        for m in re.finditer(re.escape(ole_sig), data):
            idx = m.start()
            extracted.append({
                "data": data[idx:],
                "filename": f"carved_ole_{idx}.doc",
                "extension": "doc",
                "magic_type": "Microsoft Office Legacy / OLE2 Compound Document",
                "carve_offset": idx,
                "carve_method": "OLE2_SIGNATURE",
            })

        for m in re.finditer(b"7z\xbc\xaf\x27\x1c", data):
            idx = m.start()
            extracted.append({
                "data": data[idx:],
                "filename": f"carved_archive_{idx}.7z",
                "extension": "7z",
                "magic_type": "7-Zip Archive",
                "carve_offset": idx,
                "carve_method": "7Z_SIGNATURE",
            })

        for m in re.finditer(b"Rar!\x1a\x07", data):
            idx = m.start()
            extracted.append({
                "data": data[idx:],
                "filename": f"carved_archive_{idx}.rar",
                "extension": "rar",
                "magic_type": "RAR Archive",
                "carve_offset": idx,
                "carve_method": "RAR_SIGNATURE",
            })

        for m in re.finditer(b"\x1f\x8b\x08", data):
            idx = m.start()
            if idx > 0 and data[idx-1:idx+3] == b"\x1f\x8b\x08":
                continue
            extracted.append({
                "data": data[idx:],
                "filename": f"carved_gzip_{idx}.gz",
                "extension": "gz",
                "magic_type": "GZIP Compressed Archive",
                "carve_offset": idx,
                "carve_method": "GZIP_SIGNATURE",
            })

        return extracted

    def _carve_xor_pe(self, data: bytes) -> List[Dict[str, Any]]:
        extracted = []
        if len(data) < 256:
            return extracted

        for key in range(1, 256):
            xor_mz = bytes([0x4D ^ key, 0x5A ^ key])
            pos = 0
            while True:
                idx = data.find(xor_mz, pos)
                if idx == -1 or idx + 64 > len(data):
                    break
                
                e_lfanew_raw = data[idx + 60:idx + 64]
                e_lfanew = struct.unpack("<I", bytes([b ^ key for b in e_lfanew_raw]))[0]
                
                if e_lfanew + 24 <= len(data) - idx:
                    pe_sig_raw = data[idx + e_lfanew:idx + e_lfanew + 4]
                    pe_sig = bytes([b ^ key for b in pe_sig_raw])
                    if pe_sig == b"PE\x00\x00":
                        unxord_all = bytes([b ^ key for b in data[idx:]])
                        pe_info = parse_pe(unxord_all)
                        if pe_info and pe_info.is_pe:
                            exact_size = pe_info.calculated_size
                            pe_data = unxord_all[:exact_size]
                            extracted.append({
                                "data": pe_data,
                                "filename": f"deobfuscated_xor_{hex(key)}_{idx}.exe",
                                "extension": "exe",
                                "magic_type": f"Deobfuscated XOR (Key: {hex(key)}) Windows PE Executable ({pe_info.machine_name})",
                                "carve_offset": idx,
                                "carve_method": f"XOR_DEOBFUSCATION_KEY_{hex(key)}",
                                "xor_key": key,
                                "pe_info": pe_info,
                            })
                            break
                pos = idx + 1

        return extracted

    def _carve_scripts(self, data: bytes) -> List[Dict[str, Any]]:
        extracted = []
        if len(data) < 32:
            return extracted

        ps_patterns = [
            rb"(?i)powershell(?:\.exe)?\s+.*(?:-enc|-e|-encodedcommand|-nop|-w\s+hidden|downloadstring|iex|invoke-expression)",
            rb"(?i)(?:New-Object\s+Net\.WebClient)\.(?:DownloadString|DownloadFile|DownloadData)",
            rb"(?i)\[System\.Reflection\.Assembly\]::Load",
            rb"(?i)\[System\.Convert\]::FromBase64String",
            rb"(?i)Invoke-Mimikatz|Invoke-ReflectivePEInjection|Invoke-Shellcode",
        ]
        for pat in ps_patterns:
            match = re.search(pat, data)
            if match:
                extracted.append({
                    "data": data,
                    "filename": "carved_malicious_script.ps1",
                    "extension": "ps1",
                    "magic_type": "PowerShell Malicious Script / Payload",
                    "carve_offset": match.start(),
                    "carve_method": "POWERSHELL_PATTERN",
                })
                break

        if data.startswith(b"#!/bin/sh") or data.startswith(b"#!/bin/bash") or data.startswith(b"#!/usr/bin/env bash"):
            extracted.append({
                "data": data,
                "filename": "carved_shell_script.sh",
                "extension": "sh",
                "magic_type": "Unix Shell Script",
                "carve_offset": 0,
                "carve_method": "SHEBANG_PATTERN",
            })

        if data.lower().startswith(b"@echo off") or b"setlocal enabledelayedexpansion" in data.lower():
            extracted.append({
                "data": data,
                "filename": "carved_batch_script.bat",
                "extension": "bat",
                "magic_type": "Windows Batch Script",
                "carve_offset": 0,
                "carve_method": "BATCH_PATTERN",
            })

        return extracted
