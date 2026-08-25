# PCAP Malware Decoder & Payload Extractor (`pcap-decode`)

High-performance, zero-external-dependency network forensic tool designed to carve, deobfuscate, analyze, and extract malware and payloads from PCAP and PCAPNG network traffic captures.

---

## Features

- **Multi-Format PCAP & PCAPNG Support**:
  - Classic PCAP (microsecond and nanosecond timestamps, big-endian and little-endian).
  - PCAPNG (Section Header Blocks, Interface Description Blocks, Enhanced Packet Blocks, Simple Packet Blocks).
  - Ethernet, 802.1Q / QinQ VLAN tags, Linux Cooked Capture (SLL/SLL2), IPv4 (with IP defragmentation), IPv6, TCP, and UDP.

- **Full TCP Stream Reassembly**:
  - Bidirectional stream tracking (client-to-server and server-to-client).
  - Handling of out-of-order segments, duplicate ACKs, window overlaps, and retransmissions.

- **Protocol Decoders**:
  - **HTTP/1.0 & HTTP/1.1**: Requests (POST uploads, multipart/form-data) and responses (downloads, gzip/deflate decompression, chunked transfer decoding, filename derivation).
  - **SMTP / POP3 / IMAP**: Full MIME email extraction and base64/quoted-printable attachment carving.
  - **FTP**: Active and passive mode data channel tracking and file transfer extraction.
  - **SMB / SMB2 / SMB3**: File read/write reassembly and share transfer carving.
  - **DNS**: Query inspection, suspicious high-entropy tunneling detection, and TXT/NULL record payload staging extraction.
  - **Raw Streams**: Direct carving of arbitrary TCP/UDP ports (reverse shells, Metasploit stagers, C2 beacons).

- **Malware & File Signature Carving**:
  - Windows PE executables & DLLs (calculates exact PE boundary from COFF and Section headers).
  - Single-byte XOR brute-force scanner (detects and deobfuscates XOR-encoded PE malware).
  - Linux ELF binaries & macOS Mach-O binaries.
  - Microsoft Office (DOCX, XLSX, PPTX, legacy OLE2 / Compound File Binary).
  - Archive formats (ZIP, 7-Zip, RAR, GZIP, BZIP2, Tar, XZ).
  - Scripts (PowerShell, Bash, Batch, VBScript, Python).
  - PDF documents (with active element detection).

- **Threat Analysis & Heuristics**:
  - MD5, SHA1, and SHA256 cryptographic hashing.
  - Shannon entropy calculation (detects packed, encrypted, or compressed payloads).
  - PE header inspection (packer sections like UPX/Themida/VMProtect, dangerous Win32 API imports).
  - Script heuristics (PowerShell bypass, DownloadString, Invoke-Expression, reverse shell pipes).
  - Threat scoring (0–100) and severity ranking (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - IOC extraction (embedded C2 URLs, IP addresses, domains).

- **Export & Reporting**:
  - Safely extracts payload files with sanitized naming schemes (`detailed`, `hash`, `original`).
  - Generates forensic sidecar `.meta.json` files for every extracted object.
  - Outputs comprehensive `analysis_report.json` with capture statistics and threat summary.

---

## Installation

```bash
pip install -e .
```

---

## CLI Usage

### Basic Extraction
```bash
pcap-decode capture.pcap -o ./extracted_malware
```

### Filter by Minimum Threat Level
```bash
pcap-decode capture.pcapng -o ./malware_out -m HIGH
```

### Generate JSON Report to Stdout
```bash
pcap-decode capture.pcap --json
```

### CLI Options

| Option | Description |
|---|---|
| `pcap_file` | Path to `.pcap` or `.pcapng` file |
| `-o, --output-dir` | Directory to save extracted files and reports (default: `./extracted_payloads`) |
| `-m, --min-threat` | Minimum threat level to display/export (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `--naming` | Naming convention: `detailed` (default), `hash`, or `original` |
| `--no-carve-raw` | Disable raw stream carving (only parse known protocols) |
| `--no-dump` | Skip saving binary files to disk (generate report only) |
| `--json` | Print full JSON analysis to stdout |
| `-v, --verbose` | Show detailed indicators, embedded URLs, and flow metadata |

---

## Python API

```python
from pcap_decode import PcapDecoderEngine, Exporter, analyze_pcap

# One-liner extraction
result = analyze_pcap("suspicious_traffic.pcap", output_dir="./output")

# Or programmatic inspection:
engine = PcapDecoderEngine(carve_raw_streams=True)
report = engine.decode_file("suspicious_traffic.pcap")

for f in report["extracted_files"]:
    print(f"[{f.threat_level.value}] {f.filename} ({f.size} bytes)")
    print(f"  SHA256: {f.sha256}")
    print(f"  Entropy: {f.entropy:.2f}")
    for alert in f.threat_indicators:
        print(f"  - Alert: {alert}")
```
