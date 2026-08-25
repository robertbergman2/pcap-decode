import socket
import struct
import time
from typing import List, Tuple


def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ip_id: int = 1, frag_offset: int = 0, more_frags: bool = False) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ihl_ver = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_fo = (0x2000 if more_frags else 0) | (frag_offset // 8)
    ttl = 64
    checksum = 0
    header = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, total_len, ip_id, flags_fo, ttl, proto, checksum, src_bytes, dst_bytes)
    return header + payload


def build_tcp_packet(src_port: int, dst_port: int, seq: int, ack: int, flags_dict: dict, payload: bytes) -> bytes:
    flags_byte = 0
    if flags_dict.get("FIN"): flags_byte |= 0x01
    if flags_dict.get("SYN"): flags_byte |= 0x02
    if flags_dict.get("RST"): flags_byte |= 0x04
    if flags_dict.get("PSH"): flags_byte |= 0x08
    if flags_dict.get("ACK"): flags_byte |= 0x10
    if flags_dict.get("URG"): flags_byte |= 0x20
    
    data_offset_res = (5 << 4)
    window = 65535
    checksum = 0
    urg_ptr = 0
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_res, flags_byte, window, checksum, urg_ptr)
    return header + payload


def build_udp_packet(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def build_ethernet_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def build_bacnet_app_tag(tag_number: int, value: bytes) -> bytes:
    if len(value) < 5:
        return bytes([(tag_number << 4) | len(value)]) + value
    if len(value) < 254:
        return bytes([(tag_number << 4) | 5, len(value)]) + value
    return bytes([(tag_number << 4) | 5, 254]) + struct.pack("!H", len(value)) + value


def build_bacnet_object_id(object_type: int, instance: int) -> bytes:
    return build_bacnet_app_tag(12, struct.pack("!I", ((object_type & 0x3FF) << 22) | (instance & 0x3FFFFF)))


def build_bvlc(npdu: bytes, function: int = 0x0A) -> bytes:
    return struct.pack("!BBH", 0x81, function, 4 + len(npdu)) + npdu


def build_npdu(apdu: bytes, expecting_reply: bool = False) -> bytes:
    control = 0x04 if expecting_reply else 0x00
    return bytes([0x01, control]) + apdu


def build_bacnet_confirmed_request(service: int, body: bytes = b"", invoke_id: int = 1) -> bytes:
    # PDU type 0, max-segments/max-APDU, invoke ID, service choice, then the service body.
    apdu = bytes([0x00, 0x05, invoke_id, service]) + body
    return build_bvlc(build_npdu(apdu, expecting_reply=True))


def build_bacnet_unconfirmed_request(service: int, body: bytes = b"") -> bytes:
    apdu = bytes([0x10, service]) + body
    return build_bvlc(build_npdu(apdu), function=0x0B)


def build_bacnet_complex_ack(service: int, body: bytes = b"", invoke_id: int = 1) -> bytes:
    apdu = bytes([0x30, invoke_id, service]) + body
    return build_bvlc(build_npdu(apdu))


def build_bacnet_atomic_file_body(file_data: bytes, start_position: int = 0, end_of_file: bool = True) -> bytes:
    # endOfFile BOOLEAN, then streamAccess: fileStartPosition INTEGER, fileData OCTET STRING.
    return (
        bytes([(1 << 4) | (1 if end_of_file else 0)])
        + build_bacnet_app_tag(3, struct.pack("!b", start_position))
        + build_bacnet_app_tag(6, file_data)
    )


def create_pcap_file(filepath: str, packets: List[Tuple[float, bytes]]):
    with open(filepath, "wb") as f:
        magic = b"\xd4\xc3\xb2\xa1"
        hdr = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        f.write(hdr)
        for ts, data in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            caplen = len(data)
            origlen = len(data)
            pkt_hdr = struct.pack("<IIII", sec, usec, caplen, origlen)
            f.write(pkt_hdr + data)


def create_pcapng_file(filepath: str, packets: List[Tuple[float, bytes]]):
    with open(filepath, "wb") as f:
        shb_bom = 0x1A2B3C4D
        shb_body = struct.pack("<IHHi", shb_bom, 1, 0, -1)
        shb_len = 12 + len(shb_body)
        shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
        f.write(shb)

        idb_body = struct.pack("<H2xI", 1, 65535)
        idb_len = 12 + len(idb_body)
        idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
        f.write(idb)

        for ts, data in packets:
            ts_raw = int(ts * 1e6)
            ts_high = (ts_raw >> 32) & 0xFFFFFFFF
            ts_low = ts_raw & 0xFFFFFFFF
            caplen = len(data)
            origlen = len(data)
            pad_len = (4 - (caplen % 4)) % 4
            padded_data = data + (b"\x00" * pad_len)
            epb_body = struct.pack("<IIIII", 0, ts_high, ts_low, caplen, origlen) + padded_data
            epb_len = 12 + len(epb_body)
            epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
            f.write(epb)


def make_dummy_pe(machine: int = 0x8664, payload_strings: List[bytes] = None) -> bytes:
    mz = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64
    pe_sig = b"PE\x00\x00"
    num_sections = 1
    opt_size = 240
    coff = struct.pack("<HHIIIHH", machine, num_sections, int(time.time()), 0, 0, opt_size, 0x0022)
    
    magic = 0x20B if machine == 0x8664 else 0x10B
    opt_prefix = struct.pack("<HBBIIIIIIQIIHH", magic, 1, 0, 512, 512, 0, 0x1000, 0x1000, 0x1000, 0x400000, 0x1000, 0x200, 6, 0)
    opt_pad = b"\x00" * (opt_size - len(opt_prefix))
    optional_hdr = opt_prefix + opt_pad

    sec_name = b".text\x00\x00\x00"
    sec_vsize = 512
    sec_vaddr = 0x1000
    sec_raw_size = 512
    sec_raw_offset = 0x200
    sec_hdr = struct.pack("<8sIIII12sI", sec_name, sec_vsize, sec_vaddr, sec_raw_size, sec_raw_offset, b"\x00" * 12, 0x60000020)

    hdr_data = mz + pe_sig + coff + optional_hdr + sec_hdr
    pad_to_sec = b"\x00" * max(0, sec_raw_offset - len(hdr_data))

    sec_data = bytearray(b"\x90" * 512)
    if payload_strings:
        offset = 10
        for s in payload_strings:
            sec_data[offset:offset+len(s)] = s
            offset += len(s) + 4

    return hdr_data + pad_to_sec + bytes(sec_data)
