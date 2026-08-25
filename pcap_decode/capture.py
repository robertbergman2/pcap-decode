import os
import socket
import struct
import sys
import time

from pcap_decode.pcap_reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW_IP_12,
    LINKTYPE_RAW_IP_101,
)


def capture_packets(output_file: str, count: int = 50, duration: float = 30.0, interface: str = None):
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        link_type = LINKTYPE_ETHERNET
        if interface:
            raw_sock.bind((interface, 0))
    except (PermissionError, OSError, AttributeError):
        print("[!] Permission denied / Raw sockets restricted.")
        print("    Live packet capture requires root privileges (CAP_NET_RAW / sudo).")
        print("\n    To capture traffic on your local network, run with elevated permissions:")
        print(f"      sudo python3 -m pcap_decode.capture {output_file} {count}")
        print("    Or using tcpdump/dumpcap:")
        print(f"      sudo tcpdump -i any -c {count} -w {output_file}")
        print(f"      sudo dumpcap -i any -c {count} -w {output_file}")
        return False

    raw_sock.settimeout(2.0)
    print(f"[*] Capturing up to {count} packets or {duration}s on network interface to '{output_file}'...")

    captured_packets = []
    start_time = time.time()

    try:
        while len(captured_packets) < count and (time.time() - start_time) < duration:
            try:
                data, _ = raw_sock.recvfrom(65535)
                pkt_time = time.time()
                captured_packets.append((pkt_time, data))
                sys.stdout.write(f"\r[*] Packets captured: {len(captured_packets)}/{count}")
                sys.stdout.flush()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user.")
    finally:
        raw_sock.close()

    print(f"\n[*] Writing {len(captured_packets)} packets to {output_file}...")
    with open(output_file, "wb") as fh:
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type)
        fh.write(global_header)
        for ts, pkt_data in captured_packets:
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            caplen = len(pkt_data)
            origlen = len(pkt_data)
            pkt_header = struct.pack("<IIII", sec, usec, caplen, origlen)
            fh.write(pkt_header + pkt_data)

    print(f"[+] Capture complete: {output_file}")
    return True


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "live_capture.pcap"
    pkt_limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    capture_packets(out_path, count=pkt_limit)
