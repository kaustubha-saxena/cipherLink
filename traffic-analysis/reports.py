import csv
import json
from pathlib import Path
from xml.etree import ElementTree


CSV_COLUMNS = (
    "timestamp_utc",
    "protocol",
    "transport",
    "source",
    "destination",
    "frame_length_bytes",
    "tcp_payload_bytes",
    "rtt_acked_payload_bytes",
    "retransmission",
    "latency_ms",
    "packet_number",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
)


def write_json_report(report: dict, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def write_packet_csv(samples: list[dict], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for sample in samples:
            writer.writerow({
                "timestamp_utc": sample["timestamp_utc"],
                "protocol": sample["protocol"],
                "transport": sample["transport"],
                "source": sample.get("source", ""),
                "destination": sample.get("destination", ""),
                "frame_length_bytes": sample["frame_length"],
                "tcp_payload_bytes": sample.get("tcp_payload_length", 0),
                "rtt_acked_payload_bytes": sample.get("latency_payload_length", ""),
                "retransmission": sample.get("retransmission", False),
                "latency_ms": sample.get("latency_ms", ""),
                "packet_number": sample.get("frame_number", ""),
                "source_ip": sample.get("source_ip", "") or "",
                "destination_ip": sample.get("destination_ip", "") or "",
                "source_port": sample.get("source_port", "") or "",
                "destination_port": sample.get("destination_port", "") or "",
            })
    return path


def _add_xml_value(parent: ElementTree.Element, name: str, value) -> None:
    if value is None or value == "":
        return
    child = ElementTree.SubElement(parent, name)
    child.text = str(value)


def build_xml_report(report: dict, samples: list[dict]) -> bytes:
    root = ElementTree.Element("CipherLinkTrafficReport", {"schema_version": str(report.get("schema_version", 1))})
    _add_xml_value(root, "generated_at", report.get("generated_at"))
    _add_xml_value(root, "source_capture", report.get("source_capture"))
    metrics = report.get("metrics", {})
    summary = ElementTree.SubElement(root, "summary")
    for key in (
        "packet_count", "total_bytes", "average_packet_size_bytes", "duration_seconds",
        "average_latency_ms", "latency_sample_count", "throughput_mbps", "retransmissions",
    ):
        _add_xml_value(summary, key, metrics.get(key))
    protocols = ElementTree.SubElement(summary, "protocol_counts")
    for protocol, count in sorted(metrics.get("protocol_counts", {}).items()):
        ElementTree.SubElement(protocols, "protocol", {"name": str(protocol), "count": str(count)})

    packet_list = ElementTree.SubElement(root, "packets", {"count": str(len(samples))})
    fields = (
        ("timestamp_utc", "timestamp_utc"),
        ("source_ip", "source_ip"),
        ("source_port", "source_port"),
        ("destination_ip", "destination_ip"),
        ("destination_port", "destination_port"),
        ("protocol", "protocol"),
        ("transport", "transport"),
        ("frame_length_bytes", "frame_length"),
        ("tcp_payload_bytes", "tcp_payload_length"),
        ("retransmission", "retransmission"),
        ("tcp_ack_rtt_ms", "latency_ms"),
        ("acknowledged_payload_bytes", "latency_payload_length"),
    )
    for sample in samples:
        number = sample.get("frame_number")
        packet = ElementTree.SubElement(packet_list, "packet", {"number": str(number) if number is not None else ""})
        for element_name, key in fields:
            _add_xml_value(packet, element_name, sample.get(key))
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)


def write_xml_report(report: dict, samples: list[dict], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_xml_report(report, samples))
    return path
