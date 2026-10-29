from xml.etree import ElementTree

from app.models.traffic import TrafficXmlExportRequest


def _add_value(parent: ElementTree.Element, name: str, value) -> None:
    if value is None or value == "":
        return
    element = ElementTree.SubElement(parent, name)
    element.text = str(value)


def build_xml_report(report: TrafficXmlExportRequest) -> bytes:
    root = ElementTree.Element("CipherLinkTrafficReport", {"schema_version": str(report.schema_version)})
    _add_value(root, "generated_at", report.generated_at)
    _add_value(root, "source_capture", report.source_capture)

    summary = ElementTree.SubElement(root, "summary")
    for name in (
        "packet_count", "total_bytes", "average_packet_size_bytes", "duration_seconds",
        "average_latency_ms", "latency_sample_count", "throughput_mbps", "retransmissions",
    ):
        _add_value(summary, name, report.metrics.get(name))
    protocol_counts = report.metrics.get("protocol_counts")
    protocol_element = ElementTree.SubElement(summary, "protocol_counts")
    if isinstance(protocol_counts, dict):
        for name, count in sorted(protocol_counts.items()):
            ElementTree.SubElement(protocol_element, "protocol", {"name": str(name), "count": str(count)})

    packet_list = ElementTree.SubElement(root, "packets", {"count": str(len(report.packets))})
    for record in report.packets:
        packet = ElementTree.SubElement(packet_list, "packet")
        for name in (
            "packet_number", "timestamp_utc", "source_ip", "source_port", "destination_ip",
            "destination_port", "protocol", "transport", "frame_length_bytes", "tcp_payload_bytes",
            "retransmission", "latency_ms", "acknowledged_payload_bytes",
        ):
            _add_value(packet, name, getattr(record, name))
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
