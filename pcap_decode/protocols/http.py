import gzip
import re
import urllib.parse
import zlib
from typing import Any, Dict, List, Optional, Tuple

from pcap_decode.models import FlowKey, TcpStream

try:
    import zstandard as zstd
except ImportError:
    zstd = None


def decompress_payload(data: bytes, encoding: str) -> bytes:
    if not data or not encoding:
        return data
    encoding = encoding.lower().strip()
    if encoding in ("gzip", "x-gzip"):
        try:
            return gzip.decompress(data)
        except Exception:
            try:
                return zlib.decompress(data, 16 + zlib.MAX_WBITS)
            except Exception:
                return data
    elif encoding in ("deflate", "zlib"):
        try:
            return zlib.decompress(data)
        except Exception:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except Exception:
                return data
    elif encoding == "zstd" and zstd:
        try:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        except Exception:
            return data
    return data


def dechunk_http_body(data: bytes) -> bytes:
    out = bytearray()
    idx = 0
    while idx < len(data):
        crlf = data.find(b"\r\n", idx)
        if crlf == -1:
            out.extend(data[idx:])
            break
        chunk_header = data[idx:crlf].split(b";")[0].strip()
        try:
            chunk_size = int(chunk_header, 16)
        except ValueError:
            out.extend(data[idx:])
            break
        if chunk_size == 0:
            break
        chunk_start = crlf + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > len(data):
            out.extend(data[chunk_start:])
            break
        out.extend(data[chunk_start:chunk_end])
        idx = chunk_end + 2
    return bytes(out)


def parse_http_headers(header_bytes: bytes) -> Tuple[str, Dict[str, str]]:
    lines = header_bytes.split(b"\r\n")
    if not lines or not lines[0]:
        return "", {}
    first_line = lines[0].decode("latin1", errors="replace").strip()
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        line_str = line.decode("latin1", errors="replace")
        if ":" in line_str:
            key, val = line_str.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    return first_line, headers


def extract_filename_from_headers(headers: Dict[str, str], uri: str) -> Optional[str]:
    content_disp = headers.get("content-disposition", "")
    if content_disp:
        match = re.search(r'filename\*?=(?:UTF-8\'\')?(?:"([^"]+)"|([^\s;]+))', content_disp, re.IGNORECASE)
        if match:
            fn = match.group(1) or match.group(2)
            if fn:
                return urllib.parse.unquote(fn.strip())

    if uri:
        parsed_uri = urllib.parse.urlparse(uri)
        path = parsed_uri.path
        if path and "/" in path:
            candidate = path.rstrip("/").split("/")[-1]
            if candidate and "." in candidate:
                return urllib.parse.unquote(candidate)
    return None


def parse_multipart_body(body: bytes, boundary: str) -> List[Tuple[Dict[str, str], bytes]]:
    parts: List[Tuple[Dict[str, str], bytes]] = []
    boundary_bytes = b"--" + boundary.encode("latin1")
    raw_parts = body.split(boundary_bytes)
    for raw_part in raw_parts:
        raw_part = raw_part.strip()
        if not raw_part or raw_part == b"--":
            continue
        hdr_end = raw_part.find(b"\r\n\r\n")
        if hdr_end == -1:
            continue
        hdr_data = raw_part[:hdr_end]
        part_body = raw_part[hdr_end + 4:]
        if part_body.endswith(b"\r\n"):
            part_body = part_body[:-2]
        _, part_headers = parse_http_headers(b"DUMMY / HTTP/1.1\r\n" + hdr_data)
        parts.append((part_headers, part_body))
    return parts


class HttpTransaction:
    def __init__(self):
        self.request_method: Optional[str] = None
        self.request_uri: Optional[str] = None
        self.request_version: Optional[str] = None
        self.request_headers: Dict[str, str] = {}
        self.request_body: bytes = b""
        self.response_version: Optional[str] = None
        self.response_status: Optional[int] = None
        self.response_reason: Optional[str] = None
        self.response_headers: Dict[str, str] = {}
        self.response_body: bytes = b""


class HttpDecoder:
    def parse_stream(self, stream: TcpStream) -> List[Dict[str, Any]]:
        extracted_objects: List[Dict[str, Any]] = []
        c2s = stream.client_to_server
        s2c = stream.server_to_client

        requests = self._parse_http_messages(c2s, is_request=True)
        responses = self._parse_http_messages(s2c, is_request=False)

        for req in requests:
            first_line, headers, body = req
            method, uri, ver = self._parse_request_line(first_line)
            encoding = headers.get("content-encoding", "")
            transfer_enc = headers.get("transfer-encoding", "").lower()
            
            raw_body = body
            if "chunked" in transfer_enc:
                raw_body = dechunk_http_body(raw_body)
            decoded_body = decompress_payload(raw_body, encoding)

            content_type = headers.get("content-type", "")
            if "multipart/form-data" in content_type and "boundary=" in content_type:
                b_match = re.search(r'boundary=(?:"([^"]+)"|([^\s;]+))', content_type)
                if b_match:
                    boundary = b_match.group(1) or b_match.group(2)
                    parts = parse_multipart_body(decoded_body, boundary)
                    for part_hdr, part_data in parts:
                        p_fn = extract_filename_from_headers(part_hdr, "")
                        if part_data:
                            extracted_objects.append({
                                "data": part_data,
                                "filename": p_fn or "http_upload.bin",
                                "source_protocol": "HTTP",
                                "flow": stream.flow,
                                "timestamp": stream.start_time,
                                "metadata": {
                                    "http_type": "request_upload",
                                    "method": method,
                                    "uri": uri,
                                    "host": headers.get("host", ""),
                                    "user_agent": headers.get("user-agent", ""),
                                    "part_headers": part_hdr,
                                },
                            })
            elif decoded_body and len(decoded_body) > 0:
                fn = extract_filename_from_headers(headers, uri)
                if method in ("POST", "PUT") or len(decoded_body) > 32:
                    extracted_objects.append({
                        "data": decoded_body,
                        "filename": fn or "http_post_payload.bin",
                        "source_protocol": "HTTP",
                        "flow": stream.flow,
                        "timestamp": stream.start_time,
                        "metadata": {
                            "http_type": "request_body",
                            "method": method,
                            "uri": uri,
                            "host": headers.get("host", ""),
                            "user_agent": headers.get("user-agent", ""),
                            "content_type": content_type,
                        },
                    })

        for idx, resp in enumerate(responses):
            first_line, headers, body = resp
            status_code, reason = self._parse_response_line(first_line)
            encoding = headers.get("content-encoding", "")
            transfer_enc = headers.get("transfer-encoding", "").lower()

            raw_body = body
            if "chunked" in transfer_enc:
                raw_body = dechunk_http_body(raw_body)
            decoded_body = decompress_payload(raw_body, encoding)

            matched_req_uri = ""
            matched_host = ""
            if idx < len(requests):
                _, req_hdrs, _ = requests[idx]
                _, matched_req_uri, _ = self._parse_request_line(requests[idx][0])
                matched_host = req_hdrs.get("host", "")

            fn = extract_filename_from_headers(headers, matched_req_uri)

            if decoded_body and len(decoded_body) > 0:
                extracted_objects.append({
                    "data": decoded_body,
                    "filename": fn or "http_download.bin",
                    "source_protocol": "HTTP",
                    "flow": stream.flow.reverse(),
                    "timestamp": stream.start_time,
                    "metadata": {
                        "http_type": "response_body",
                        "status_code": status_code,
                        "reason": reason,
                        "uri": matched_req_uri,
                        "host": matched_host,
                        "content_type": headers.get("content-type", ""),
                        "content_encoding": encoding,
                        "response_headers": headers,
                    },
                })

        return extracted_objects

    def _parse_request_line(self, line: str) -> Tuple[str, str, str]:
        parts = line.split(" ", 2)
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], "HTTP/1.1"
        return "", "", ""

    def _parse_response_line(self, line: str) -> Tuple[int, str]:
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
                reason = parts[2] if len(parts) > 2 else ""
                return status, reason
            except ValueError:
                pass
        return 0, ""

    def _parse_http_messages(self, data: bytes, is_request: bool) -> List[Tuple[str, Dict[str, str], bytes]]:
        messages: List[Tuple[str, Dict[str, str], bytes]] = []
        offset = 0
        total_len = len(data)

        while offset < total_len:
            hdr_end = data.find(b"\r\n\r\n", offset)
            if hdr_end == -1:
                break

            hdr_bytes = data[offset:hdr_end]
            first_line, headers = parse_http_headers(hdr_bytes)
            if not first_line:
                break

            if is_request:
                is_valid = any(first_line.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "))
            else:
                is_valid = first_line.startswith("HTTP/")

            if not is_valid:
                offset = hdr_end + 4
                continue

            body_start = hdr_end + 4
            content_length = None
            if "content-length" in headers:
                try:
                    content_length = int(headers["content-length"])
                except ValueError:
                    content_length = None

            transfer_enc = headers.get("transfer-encoding", "").lower()

            if content_length is not None:
                body_end = min(total_len, body_start + content_length)
                body = data[body_start:body_end]
                messages.append((first_line, headers, body))
                offset = body_end
            elif "chunked" in transfer_enc:
                chunk_term = data.find(b"0\r\n\r\n", body_start)
                if chunk_term != -1:
                    body_end = chunk_term + 5
                    body = data[body_start:body_end]
                    messages.append((first_line, headers, body))
                    offset = body_end
                else:
                    body = data[body_start:]
                    messages.append((first_line, headers, body))
                    break
            else:
                next_msg = -1
                if is_request:
                    for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT "):
                        pos = data.find(m, body_start)
                        if pos != -1 and (next_msg == -1 or pos < next_msg):
                            next_msg = pos
                else:
                    pos = data.find(b"HTTP/", body_start)
                    if pos != -1:
                        next_msg = pos

                if next_msg != -1:
                    body = data[body_start:next_msg]
                    messages.append((first_line, headers, body))
                    offset = next_msg
                else:
                    body = data[body_start:]
                    messages.append((first_line, headers, body))
                    break

        return messages
