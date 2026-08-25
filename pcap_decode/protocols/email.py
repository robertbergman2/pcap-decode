import email
import email.policy
import re
from typing import Any, Dict, List, Optional

from pcap_decode.models import TcpStream


class EmailDecoder:
    def parse_stream(self, stream: TcpStream) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        c2s = stream.client_to_server
        s2c = stream.server_to_client

        ports = (stream.flow.src_port, stream.flow.dst_port)
        is_smtp = any(p in (25, 465, 587, 2525) for p in ports) or b"220 " in s2c[:100] or b"HELO" in c2s[:100] or b"EHLO" in c2s[:100]
        is_pop3 = any(p in (110, 995) for p in ports) or b"+OK" in s2c[:50]
        is_imap = any(p in (143, 993) for p in ports) or b"* OK" in s2c[:50]

        if not (is_smtp or is_pop3 or is_imap):
            if b"From: " in c2s or b"Subject: " in c2s or b"Content-Type: " in c2s:
                is_smtp = True
            elif b"From: " in s2c or b"Subject: " in s2c or b"Content-Type: " in s2c:
                is_pop3 = True

        if is_smtp:
            raw_emails = self._extract_smtp_messages(c2s)
            for raw_msg in raw_emails:
                extracted.extend(self._process_email_bytes(raw_msg, stream, "SMTP"))

        if is_pop3 or is_imap:
            raw_emails = self._extract_pop3_imap_messages(s2c)
            for raw_msg in raw_emails:
                proto = "POP3" if is_pop3 else "IMAP"
                extracted.extend(self._process_email_bytes(raw_msg, stream, proto))

        return extracted

    def _extract_smtp_messages(self, data: bytes) -> List[bytes]:
        messages: List[bytes] = []
        matches = list(re.finditer(rb"(?:^|\r?\n)DATA\r?\n", data, re.IGNORECASE))
        if not matches:
            if b"From:" in data and b"Subject:" in data:
                return [data]
            return []

        for m in matches:
            start_pos = m.end()
            term_match = re.search(rb"\r?\n\.\r?\n", data[start_pos:])
            if term_match:
                end_pos = start_pos + term_match.start()
                msg_bytes = data[start_pos:end_pos]
                messages.append(msg_bytes)
            else:
                msg_bytes = data[start_pos:]
                if msg_bytes:
                    messages.append(msg_bytes)

        return messages

    def _extract_pop3_imap_messages(self, data: bytes) -> List[bytes]:
        messages: List[bytes] = []
        ok_markers = [m.start() for m in re.finditer(rb"\+OK[^\r\n]*\r?\n", data)]
        if ok_markers:
            for marker in ok_markers:
                start_pos = data.find(b"\n", marker) + 1
                term_match = re.search(rb"\r?\n\.\r?\n", data[start_pos:])
                if term_match:
                    end_pos = start_pos + term_match.start()
                    messages.append(data[start_pos:end_pos])
                else:
                    messages.append(data[start_pos:])
        elif b"From:" in data and (b"Subject:" in data or b"Content-Type:" in data):
            messages.append(data)
        return messages

    def _process_email_bytes(self, raw_bytes: bytes, stream: TcpStream, proto: str) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception:
            return []

        sender = str(msg.get("From", ""))
        to = str(msg.get("To", ""))
        subject = str(msg.get("Subject", ""))
        date = str(msg.get("Date", ""))
        msg_id = str(msg.get("Message-ID", ""))

        for part in msg.walk():
            filename = part.get_filename()
            content_type = part.get_content_type()
            content_disp = part.get_content_disposition()

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            is_attachment = (content_disp == "attachment") or (filename is not None)
            if not is_attachment and content_type not in ("text/plain", "text/html", "multipart/mixed", "multipart/alternative"):
                is_attachment = True

            if is_attachment or (len(payload) > 512 and filename):
                extracted.append({
                    "data": payload,
                    "filename": filename or "email_attachment.bin",
                    "source_protocol": proto,
                    "flow": stream.flow,
                    "timestamp": stream.start_time,
                    "metadata": {
                        "from": sender,
                        "to": to,
                        "subject": subject,
                        "date": date,
                        "message_id": msg_id,
                        "content_type": content_type,
                        "content_disposition": content_disp,
                    },
                })

        return extracted
