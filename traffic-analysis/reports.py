import csv
import json
from pathlib import Path


CSV_COLUMNS = (
    "timestamp_utc",
    "protocol",
    "transport",
    "source",
    "destination",
    "frame_length_bytes",
    "tcp_payload_bytes",
    "retransmission",
    "latency_ms",
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
                "retransmission": sample.get("retransmission", False),
                "latency_ms": sample.get("latency_ms", ""),
            })
    return path
