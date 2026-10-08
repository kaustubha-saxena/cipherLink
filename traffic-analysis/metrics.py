from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import ceil


SIZE_BUCKETS = (
    (0, 63, "0-63 B"),
    (64, 127, "64-127 B"),
    (128, 255, "128-255 B"),
    (256, 511, "256-511 B"),
    (512, 1023, "512 B-1 KB"),
    (1024, 1518, "1-1.5 KB"),
    (1519, None, ">1.5 KB"),
)


def build_report(samples: list[dict], source_capture: str) -> dict:
    packet_count = len(samples)
    total_bytes = sum(sample["frame_length"] for sample in samples)
    timestamps = [sample["timestamp"] for sample in samples]
    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    duration = max(0.0, end - start) if start is not None else 0.0
    average_packet_size = total_bytes / packet_count if packet_count else 0.0

    protocol_counts = Counter(sample["protocol"] for sample in samples)
    packets_by_second = defaultdict(int)
    bytes_by_second = defaultdict(int)
    size_counts = Counter()
    flow_counts = Counter()
    latency_samples = []
    retransmissions = 0

    for sample in samples:
        second = max(0, int(sample["timestamp"] - start)) if start is not None else 0
        packets_by_second[second] += 1
        bytes_by_second[second] += sample["frame_length"]
        for minimum, maximum, label in SIZE_BUCKETS:
            if sample["frame_length"] >= minimum and (maximum is None or sample["frame_length"] <= maximum):
                size_counts[label] += 1
                break
        if sample.get("retransmission"):
            retransmissions += 1
        if sample.get("latency_ms") is not None:
            latency_samples.append(sample["latency_ms"])
        if sample.get("source") or sample.get("destination"):
            flow_counts[(sample.get("source") or "unknown", sample.get("destination") or "unknown", sample["transport"])] += 1

    duration_slots = max(1, ceil(duration) if duration else (1 if packet_count else 0))
    packet_timeline = [{"second": second, "count": packets_by_second[second]} for second in range(duration_slots)]
    throughput_timeline = [
        {"second": second, "mbps": round(bytes_by_second[second] * 8 / 1_000_000, 6)}
        for second in range(duration_slots)
    ]
    size_distribution = [{"bucket": label, "count": size_counts[label]} for _, _, label in SIZE_BUCKETS]
    avg_latency = sum(latency_samples) / len(latency_samples) if latency_samples else None
    top_flows = [
        {"source": source, "destination": destination, "transport": transport, "packets": count}
        for (source, destination, transport), count in flow_counts.most_common(12)
    ]

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_capture": source_capture,
        "metrics": {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "average_packet_size_bytes": round(average_packet_size, 2),
            "duration_seconds": round(duration, 3),
            "average_latency_ms": round(avg_latency, 3) if avg_latency is not None else None,
            "throughput_mbps": round(total_bytes * 8 / duration / 1_000_000, 6) if duration > 0 else None,
            "retransmissions": retransmissions,
            "latency_sample_count": len(latency_samples),
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "packet_count_by_second": packet_timeline,
            "packet_size_distribution": size_distribution,
            "throughput_mbps_by_second": throughput_timeline,
            "latency_by_packet_size": [
                {"packet_size_bytes": sample["frame_length"], "latency_ms": sample["latency_ms"]}
                for sample in samples if sample.get("latency_ms") is not None
            ][:500],
            "top_flows": top_flows,
        },
    }
