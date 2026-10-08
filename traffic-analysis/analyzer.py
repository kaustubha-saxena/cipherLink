import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pyshark
except ImportError as error:
    raise SystemExit("PyShark is not installed. Run: python -m pip install -r traffic-analysis/requirements.txt") from error

from metrics import build_report
from reports import write_json_report, write_packet_csv


def optional_field(layer, name: str):
    try:
        value = getattr(layer, name)
        return str(value) if value is not None else None
    except (AttributeError, KeyError, TypeError):
        return None


def packet_to_sample(packet) -> dict:
    frame_length = int(packet.length)
    timestamp = float(packet.sniff_timestamp)
    layers = {str(layer.layer_name).lower() for layer in packet.layers}
    transport = str(getattr(packet, "transport_layer", None) or "OTHER").upper()
    protocol = str(getattr(packet, "highest_layer", None) or transport).upper()

    source = None
    destination = None
    network = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
    if network is not None:
        source = optional_field(network, "src")
        destination = optional_field(network, "dst")
    if transport == "TCP":
        source_port = optional_field(packet.tcp, "srcport")
        destination_port = optional_field(packet.tcp, "dstport")
    elif transport == "UDP":
        source_port = optional_field(packet.udp, "srcport")
        destination_port = optional_field(packet.udp, "dstport")
    else:
        source_port = destination_port = None
    if source and source_port:
        source = f"{source}:{source_port}"
    if destination and destination_port:
        destination = f"{destination}:{destination_port}"

    tcp_payload_length = 0
    latency_ms = None
    retransmission = False
    if "tcp" in layers:
        tcp_payload_length = int(optional_field(packet.tcp, "len") or 0)
        analysis = getattr(packet.tcp, "analysis", None)
        if analysis is not None:
            retransmission = any(
                optional_field(analysis, field) is not None
                for field in ("retransmission", "fast_retransmission", "spurious_retransmission")
            )
            raw_rtt = optional_field(analysis, "ack_rtt")
            try:
                latency_ms = float(raw_rtt) * 1000 if raw_rtt is not None else None
            except ValueError:
                latency_ms = None

    return {
        "timestamp": timestamp,
        "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "protocol": protocol,
        "transport": transport,
        "source": source,
        "destination": destination,
        "frame_length": frame_length,
        "tcp_payload_length": tcp_payload_length,
        "retransmission": retransmission,
        "latency_ms": latency_ms,
    }


def analyze_capture(capture_path: Path) -> tuple[dict, list[dict]]:
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")
    samples = []
    capture = pyshark.FileCapture(str(capture_path), keep_packets=False)
    try:
        for packet in capture:
            try:
                samples.append(packet_to_sample(packet))
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
    finally:
        capture.close()
    report = build_report(samples, capture_path.name)
    return report, samples


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a Wireshark PCAP/PCAPNG file and export CipherLink traffic metrics.")
    parser.add_argument("capture", type=Path, help="Input .pcap or .pcapng capture")
    parser.add_argument("--json", dest="json_path", type=Path, help="JSON dashboard report (default: <capture>.analysis.json)")
    parser.add_argument("--csv", dest="csv_path", type=Path, help="Optional per-packet CSV export")
    args = parser.parse_args()

    try:
        report, samples = analyze_capture(args.capture)
        json_path = args.json_path or args.capture.with_suffix(".analysis.json")
        write_json_report(report, json_path)
        print(f"Analyzed {report['metrics']['packet_count']} packets -> {json_path}")
        if args.csv_path:
            write_packet_csv(samples, args.csv_path)
            print(f"Packet details -> {args.csv_path}")
        return 0
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
