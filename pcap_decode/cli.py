import argparse
import json
import sys
from typing import List

from pcap_decode.engine import PcapDecoderEngine
from pcap_decode.exporter import Exporter
from pcap_decode.models import ThreatLevel

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def format_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def get_threat_badge(level: ThreatLevel) -> str:
    badges = {
        ThreatLevel.CRITICAL: "[bold white on red] CRITICAL [/]",
        ThreatLevel.HIGH: "[bold white on dark_orange]  HIGH   [/]",
        ThreatLevel.MEDIUM: "[bold black on yellow] MEDIUM  [/]",
        ThreatLevel.LOW: "[bold white on blue]   LOW   [/]",
        ThreatLevel.INFO: "[bold white on grey50]  INFO   [/]",
    }
    return badges.get(level, str(level.value))


def print_rich_results(console: "Console", result: dict, export_info: dict, min_level: ThreatLevel, verbose: bool):
    summary = result.get("threat_summary", {})
    files = result.get("extracted_files", [])

    level_order = [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW, ThreatLevel.INFO]
    min_idx = level_order.index(min_level)
    allowed_levels = set(level_order[:min_idx + 1])

    filtered_files = [f for f in files if f.threat_level in allowed_levels]

    console.print()
    console.print(Panel.fit(
        f"[bold cyan]PCAP Malware Decoder & Payload Extractor[/]\n"
        f"Input: [green]{result['pcap_path']}[/]\n"
        f"Packets: [yellow]{result['packets_count']}[/] | TCP Streams: [yellow]{result['tcp_streams_count']}[/] | UDP Packets: [yellow]{result['udp_packets_count']}[/]\n"
        f"Processing Time: [bold]{result['processing_time_seconds']}s[/]",
        title="[bold blue]Capture Summary[/]",
        border_style="blue"
    ))

    sum_table = Table(title="Extracted Objects & Threat Classification", show_header=True, header_style="bold magenta")
    sum_table.add_column("Threat Level", justify="center")
    sum_table.add_column("Count", justify="right")
    sum_table.add_column("Description")

    sum_table.add_row(get_threat_badge(ThreatLevel.CRITICAL), str(summary.get("CRITICAL", 0)), "Confirmed malicious payloads / shellcode / exploits / deobfuscated malware")
    sum_table.add_row(get_threat_badge(ThreatLevel.HIGH), str(summary.get("HIGH", 0)), "Executables, suspicious scripts, known packer sections, dangerous APIs")
    sum_table.add_row(get_threat_badge(ThreatLevel.MEDIUM), str(summary.get("MEDIUM", 0)), "High entropy streams, active office documents, unusual payloads")
    sum_table.add_row(get_threat_badge(ThreatLevel.LOW), str(summary.get("LOW", 0)), "Transferred binaries/archives with standard signatures")
    sum_table.add_row(get_threat_badge(ThreatLevel.INFO), str(summary.get("INFO", 0)), "General files, HTML, text, or non-malicious objects")

    console.print(sum_table)

    if filtered_files:
        files_table = Table(title=f"Extracted Payloads ({len(filtered_files)} items)", show_header=True, header_style="bold cyan")
        files_table.add_column("Level", justify="center", width=12)
        files_table.add_column("Filename", style="bold green", no_wrap=False)
        files_table.add_column("Type", style="yellow")
        files_table.add_column("Protocol", style="cyan")
        files_table.add_column("Size", justify="right")
        files_table.add_column("Entropy", justify="right")
        files_table.add_column("SHA256 (First 16)", style="dim")

        for f in filtered_files:
            files_table.add_row(
                get_threat_badge(f.threat_level),
                f.filename,
                f.magic_type[:30] + ("..." if len(f.magic_type) > 30 else ""),
                f.source_protocol,
                format_size(f.size),
                f"{f.entropy:.2f}",
                f.sha256[:16] + "...",
            )

        console.print(files_table)

        if verbose or any(f.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH) for f in filtered_files):
            console.print("\n[bold red]Threat Detection Details:[/]")
            for f in filtered_files:
                if f.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH) or verbose:
                    flow_str = str(f.flow) if f.flow else "Unknown Flow"
                    console.print(f"  • [bold]{f.filename}[/] ([cyan]{f.source_protocol}[/], [yellow]{flow_str}[/])")
                    console.print(f"    SHA256: [dim]{f.sha256}[/]")
                    for ind in f.threat_indicators:
                        console.print(f"    - [red]Alert:[/] {ind}")
                    if verbose and f.metadata:
                        console.print(f"    - [dim]Metadata: {json.dumps(f.metadata, default=str)}[/]")

    if result.get("suspicious_domains"):
        dom_table = Table(title="Suspicious DNS Tunneling / Queries Detected", show_header=True, header_style="bold red")
        dom_table.add_column("Domain")
        dom_table.add_column("Entropy", justify="right")
        dom_table.add_column("Length", justify="right")
        for dom in result["suspicious_domains"]:
            dom_table.add_row(dom["domain"], f"{dom['entropy']:.2f}", str(dom["length"]))
        console.print(dom_table)

    print_rich_bacnet(console, result.get("bacnet") or {}, verbose)

    raw_carving = result.get("raw_carving") or {}
    suppressed = raw_carving.get("raw_udp_packets_suppressed", 0)
    if suppressed:
        reasons = ", ".join(f"{k}={v}" for k, v in sorted(raw_carving.get("by_reason", {}).items()))
        console.print(
            f"\n[dim]Raw UDP carving suppressed for {suppressed} packet(s) ({reasons}). "
            f"Telemetry ports and per-flow cap of {raw_carving.get('max_candidates_per_flow')} applied.[/]"
        )

    if export_info.get("output_dir"):
        console.print(f"\n[bold green]Payloads and Forensic Report exported to:[/] [bold underline]{export_info['output_dir']}[/]")
        if export_info.get("report_path"):
            console.print(f"[green]Report JSON:[/] {export_info['report_path']}\n")


def print_rich_bacnet(console: "Console", bacnet: dict, verbose: bool):
    if not bacnet.get("packets_decoded"):
        return

    console.print(Panel.fit(
        f"BACnet/IP packets decoded: [yellow]{bacnet['packets_decoded']}[/]"
        f" | Malformed: [yellow]{bacnet.get('malformed_packets', 0)}[/]"
        f" | Devices seen: [yellow]{len(bacnet.get('devices', []))}[/]",
        title="[bold blue]BACnet / OT Traffic[/]",
        border_style="blue"
    ))

    services = bacnet.get("services") or {}
    if services:
        svc_table = Table(title="BACnet Services", show_header=True, header_style="bold magenta")
        svc_table.add_column("Service")
        svc_table.add_column("Count", justify="right")
        for name, count in list(services.items())[:15 if not verbose else 100]:
            svc_table.add_row(name, str(count))
        console.print(svc_table)

    observations = bacnet.get("observations") or []
    if observations:
        obs_table = Table(title="Control-Plane Activity (writes, file transfers, device control)", show_header=True, header_style="bold red")
        obs_table.add_column("Service", style="bold")
        obs_table.add_column("Source")
        obs_table.add_column("Destination")
        obs_table.add_column("Count", justify="right")
        obs_table.add_column("Detail / Note")
        for obs in observations[:20 if not verbose else 500]:
            detail = "; ".join(obs.get("details") or []) or obs.get("note", "")
            obs_table.add_row(obs["service"], obs.get("src_ip") or "-", obs.get("dst_ip") or "-", str(obs["count"]), detail)
        console.print(obs_table)

    devices = bacnet.get("devices") or []
    if devices and verbose:
        dev_table = Table(title="BACnet Device Inventory (from I-Am)", show_header=True, header_style="bold cyan")
        dev_table.add_column("Device Instance", justify="right")
        dev_table.add_column("Address")
        dev_table.add_column("Relayed By")
        dev_table.add_column("Vendor ID", justify="right")
        dev_table.add_column("Max APDU", justify="right")
        for dev in devices[:200]:
            dev_table.add_row(
                str(dev["device_instance"]),
                str(dev.get("address") or "-"),
                str(dev.get("relayed_by", "-")),
                str(dev.get("vendor_id", "-")),
                str(dev.get("max_apdu_length", "-")),
            )
        console.print(dev_table)

    for scanner in bacnet.get("enumeration_sources") or []:
        console.print(
            f"[bold yellow]Enumeration:[/] {scanner['src_ip']} issued "
            f"{scanner['who_is_count']} Who-Is requests"
        )


def print_plain_results(result: dict, export_info: dict, min_level: ThreatLevel, verbose: bool):
    summary = result.get("threat_summary", {})
    files = result.get("extracted_files", [])

    level_order = [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW, ThreatLevel.INFO]
    min_idx = level_order.index(min_level)
    allowed_levels = set(level_order[:min_idx + 1])
    filtered_files = [f for f in files if f.threat_level in allowed_levels]

    print("=" * 70)
    print("PCAP Malware Decoder & Payload Extractor")
    print(f"Input File:      {result['pcap_path']}")
    print(f"Packets Processed: {result['packets_count']}")
    print(f"TCP Streams:     {result['tcp_streams_count']}")
    print(f"Extracted Files: {len(files)}")
    print(f"Processing Time: {result['processing_time_seconds']}s")
    print("-" * 70)
    print("Threat Breakdown:")
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {k:8s}: {summary.get(k, 0)}")
    print("-" * 70)
    print(f"Extracted Files ({len(filtered_files)} displayed):")
    for f in filtered_files:
        print(f"[{f.threat_level.value:8s}] {f.filename} ({format_size(f.size)}) - {f.magic_type}")
        print(f"           Proto: {f.source_protocol} | SHA256: {f.sha256}")
        if f.flow:
            print(f"           Flow:  {f.flow}")
        for ind in f.threat_indicators:
            print(f"           Alert: {ind}")

    bacnet = result.get("bacnet") or {}
    if bacnet.get("packets_decoded"):
        print("-" * 70)
        print("BACnet / OT Traffic:")
        print(f"  Packets decoded:  {bacnet['packets_decoded']}")
        print(f"  Malformed:        {bacnet.get('malformed_packets', 0)}")
        print(f"  Devices seen:     {len(bacnet.get('devices', []))}")
        services = bacnet.get("services") or {}
        if services:
            print("  Services:")
            for name, count in list(services.items())[:15 if not verbose else 100]:
                print(f"    {name}: {count}")
        observations = bacnet.get("observations") or []
        if observations:
            print("  Control-plane activity:")
            for obs in observations[:20 if not verbose else 500]:
                detail = "; ".join(obs.get("details") or []) or obs.get("note", "")
                print(f"    [{obs['count']:6d}x] {obs['service']}: {obs.get('src_ip')} -> {obs.get('dst_ip')} | {detail}")
        for scanner in bacnet.get("enumeration_sources") or []:
            print(f"  Enumeration: {scanner['src_ip']} issued {scanner['who_is_count']} Who-Is requests")

    raw_carving = result.get("raw_carving") or {}
    if raw_carving.get("raw_udp_packets_suppressed"):
        reasons = ", ".join(f"{k}={v}" for k, v in sorted(raw_carving.get("by_reason", {}).items()))
        print("-" * 70)
        print(f"Raw UDP carving suppressed for {raw_carving['raw_udp_packets_suppressed']} packet(s) ({reasons})")

    print("=" * 70)
    if export_info.get("output_dir"):
        print(f"Export directory: {export_info['output_dir']}")
        if export_info.get("report_path"):
            print(f"Report path:      {export_info['report_path']}")


def main(args: list = None):
    parser = argparse.ArgumentParser(
        description="PCAP Malware Decoder & Payload Extractor - Carves and analyzes malware from PCAP/PCAPNG network captures.",
    )
    parser.add_argument("pcap_file", help="Path to input PCAP or PCAPNG capture file")
    parser.add_argument("-o", "--output-dir", default="extracted_payloads", help="Output directory for extracted payloads and metadata (default: ./extracted_payloads)")
    parser.add_argument("-m", "--min-threat", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="INFO", help="Minimum threat level to display/export (default: INFO)")
    parser.add_argument("--naming", choices=["detailed", "hash", "original"], default="detailed", help="File naming convention (default: detailed)")
    parser.add_argument("--no-carve-raw", action="store_true", help="Disable raw stream carving (only parse standard protocols)")
    parser.add_argument("--no-dump", action="store_true", help="Skip writing carved binary payload files to disk (report only)")
    parser.add_argument("--json", action="store_true", help="Output full JSON report to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display verbose threat indicators and metadata")

    parsed = parser.parse_args(args)

    engine = PcapDecoderEngine(carve_raw_streams=not parsed.no_carve_raw)
    try:
        result = engine.decode_file(parsed.pcap_file)
    except Exception as e:
        sys.stderr.write(f"Error parsing PCAP file {parsed.pcap_file}: {e}\n")
        sys.exit(1)

    exporter = Exporter(output_dir=parsed.output_dir, naming_scheme=parsed.naming)
    export_info = exporter.export(result, save_raw_files=not parsed.no_dump, save_report=True)

    if parsed.json:
        print(json.dumps(export_info["summary"], indent=2))
        return

    min_threat_level = ThreatLevel(parsed.min_threat)
    if HAS_RICH and sys.stdout.isatty():
        console = Console()
        print_rich_results(console, result, export_info, min_threat_level, parsed.verbose)
    else:
        print_plain_results(result, export_info, min_threat_level, parsed.verbose)


if __name__ == "__main__":
    main()
