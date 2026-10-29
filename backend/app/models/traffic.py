from typing import Any

from pydantic import BaseModel, Field


class TrafficPacketRecord(BaseModel):
    packet_number: int | None = None
    timestamp_utc: str | None = Field(default=None, max_length=80)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=64)
    transport: str | None = Field(default=None, max_length=16)
    frame_length_bytes: int | None = Field(default=None, ge=0)
    tcp_payload_bytes: int | None = Field(default=None, ge=0)
    retransmission: bool | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    acknowledged_payload_bytes: int | None = Field(default=None, ge=0)


class TrafficXmlExportRequest(BaseModel):
    schema_version: int = 1
    generated_at: str | None = Field(default=None, max_length=80)
    source_capture: str = Field(min_length=1, max_length=255)
    metrics: dict[str, Any] = Field(default_factory=dict)
    packets: list[TrafficPacketRecord] = Field(max_length=100_000)
