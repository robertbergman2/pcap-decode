import json
import os
import re
from typing import Any, Dict, List, Optional

from pcap_decode.models import ExtractedFile


def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r'[\\/*?:"<>|]', "_", name)
    cleaned = cleaned.strip(" .\r\n\t")
    if not cleaned:
        cleaned = "extracted_payload.bin"
    return cleaned


class Exporter:
    def __init__(self, output_dir: str = "extracted_malware", naming_scheme: str = "detailed"):
        self.output_dir = output_dir
        self.naming_scheme = naming_scheme

    def export(self, analysis_result: Dict[str, Any], save_raw_files: bool = True, save_report: bool = True) -> Dict[str, Any]:
        os.makedirs(self.output_dir, exist_ok=True)
        files_dir = os.path.join(self.output_dir, "files")
        if save_raw_files:
            os.makedirs(files_dir, exist_ok=True)

        saved_files_metadata = []
        files: List[ExtractedFile] = analysis_result.get("extracted_files", [])

        used_names = set()

        for f in files:
            clean_name = sanitize_filename(f.filename)
            base, ext = os.path.splitext(clean_name)
            if not ext and f.extension:
                ext = f".{f.extension}"
                clean_name = f"{base}{ext}"

            if self.naming_scheme == "hash":
                target_filename = f"{f.sha256[:16]}_{clean_name}"
            elif self.naming_scheme == "detailed":
                flow_str = f"{f.flow.src_ip}_{f.flow.src_port}" if f.flow else "unknown"
                proto_str = f.source_protocol.replace(":", "_").replace("/", "_")
                target_filename = f"{proto_str}_{flow_str}_{clean_name}"
            else:
                target_filename = clean_name

            target_filename = sanitize_filename(target_filename)
            uniq_name = target_filename
            counter = 1
            while uniq_name in used_names:
                uniq_base, uniq_ext = os.path.splitext(target_filename)
                uniq_name = f"{uniq_base}_{counter}{uniq_ext}"
                counter += 1
            used_names.add(uniq_name)

            file_path = os.path.join(files_dir, uniq_name)
            meta_path = os.path.join(files_dir, f"{uniq_name}.meta.json")

            if save_raw_files:
                with open(file_path, "wb") as fh:
                    fh.write(f.data)

                meta_dict = f.to_dict(include_data=False)
                meta_dict["saved_path"] = file_path
                with open(meta_path, "w", encoding="utf-8") as mh:
                    json.dump(meta_dict, mh, indent=2)

            file_meta = f.to_dict(include_data=False)
            file_meta["saved_filename"] = uniq_name
            file_meta["saved_path"] = file_path if save_raw_files else None
            saved_files_metadata.append(file_meta)

        report_data = {
            "pcap_path": analysis_result.get("pcap_path"),
            "packets_count": analysis_result.get("packets_count"),
            "tcp_streams_count": analysis_result.get("tcp_streams_count"),
            "udp_packets_count": analysis_result.get("udp_packets_count"),
            "extracted_files_count": len(files),
            "threat_summary": analysis_result.get("threat_summary"),
            "suspicious_domains": analysis_result.get("suspicious_domains"),
            "raw_carving": analysis_result.get("raw_carving"),
            "processing_time_seconds": analysis_result.get("processing_time_seconds"),
            "extracted_files": saved_files_metadata,
        }

        report_path = os.path.join(self.output_dir, "analysis_report.json")
        if save_report:
            with open(report_path, "w", encoding="utf-8") as rh:
                json.dump(report_data, rh, indent=2)

        return {
            "output_dir": os.path.abspath(self.output_dir),
            "report_path": os.path.abspath(report_path) if save_report else None,
            "exported_files_count": len(files),
            "summary": report_data,
        }
