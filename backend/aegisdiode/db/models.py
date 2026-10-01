"""
AegisDiode Data Models
======================
Pydantic models for all core entities in the pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────

class FlowState(str, Enum):
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DetectorType(str, Enum):
    IAT = "iat"
    SIZE = "size"
    ENTROPY = "entropy"
    RATE = "rate"


class Classification(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# ─── Packet ───────────────────────────────────────────────────────

class PacketMeta(BaseModel):
    """Minimal metadata extracted from a raw packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6  # TCP default
    size: int = 0
    payload_bytes: bytes = b""


# ─── Flow Key ─────────────────────────────────────────────────────

class FlowKey(BaseModel):
    """5-tuple flow identifier."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def to_string(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"


# ─── Observation Flow ─────────────────────────────────────────────

class ObservationFlow(BaseModel):
    """A unidirectional observation flow tracked by the flow keying engine."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    flow_key: FlowKey
    state: FlowState = FlowState.ACTIVE
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Transient — not persisted
    packets: list[PacketMeta] = Field(default=[], exclude=True)

    def to_dict(self) -> dict:
        d = self.model_dump(mode="json")
        d["src_ip"] = self.flow_key.src_ip
        d["dst_ip"] = self.flow_key.dst_ip
        d["src_port"] = self.flow_key.src_port
        d["dst_port"] = self.flow_key.dst_port
        d["protocol"] = self.flow_key.protocol
        return d


# ─── Flow Features ────────────────────────────────────────────────

class IATFeatures(BaseModel):
    """Inter-Arrival Time statistics."""
    mean: float = 0.0
    std: float = 0.0
    min: float = 0.0
    max: float = 0.0
    median: float = 0.0
    cv: float = 0.0  # Coefficient of variation (std/mean)


class SizeFeatures(BaseModel):
    """Packet size statistics."""
    mean: float = 0.0
    std: float = 0.0
    min: float = 0.0
    max: float = 0.0
    bytes_per_sec: float = 0.0
    histogram: list[float] = Field(default_factory=lambda: [0.0] * 8)


class EntropyFeatures(BaseModel):
    """Shannon entropy features."""
    value: float = 0.0  # 0.0 to 8.0 bits
    change_rate: float = 0.0  # Entropy change per extraction window


class FlowFeatures(BaseModel):
    """Complete feature vector for one extraction window."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    flow_id: str
    timestamp: float = 0.0
    packet_count: int = 0
    iat: IATFeatures = Field(default_factory=IATFeatures)
    size: SizeFeatures = Field(default_factory=SizeFeatures)
    entropy: EntropyFeatures = Field(default_factory=EntropyFeatures)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── Baseline ─────────────────────────────────────────────────────

class BaselineRecord(BaseModel):
    """Rolling baseline for a feature set, keyed by flow pattern."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    pattern_key: str  # Generalized flow pattern (e.g., "tcp:80" for all HTTP)
    observation_count: int = 0
    last_updated: float = 0.0

    # Per-feature baselines (median + MAD)
    iat_median: float = 0.0
    iat_mad: float = 1.0  # Default to 1.0 to avoid div-by-zero
    size_median: float = 0.0
    size_mad: float = 1.0
    entropy_median: float = 0.0
    entropy_mad: float = 1.0
    rate_median: float = 0.0
    rate_mad: float = 1.0

    # Drift-rejection state
    drift_rejected_count: int = 0
    last_drift_event: Optional[float] = None

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── Alert ────────────────────────────────────────────────────────

class Alert(BaseModel):
    """Single-detector anomaly alert."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    flow_id: str
    flow_key_str: str = ""
    detector_type: DetectorType
    severity: Severity
    confidence: float = 0.0  # 0.0 to 1.0
    z_score: float = 0.0
    description: str = ""
    feature_values: dict = Field(default_factory=dict)
    baseline_values: dict = Field(default_factory=dict)
    timestamp: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── Incident ─────────────────────────────────────────────────────

class Incident(BaseModel):
    """Correlated multi-signal incident."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    alert_ids: list[str] = Field(default_factory=list)
    detector_types: list[str] = Field(default_factory=list)
    threat_score: float = 0.0
    classification: Classification = Classification.LOW
    status: IncidentStatus = IncidentStatus.OPEN
    target_ip: str = ""
    source_ips: list[str] = Field(default_factory=list)
    affected_flow_ids: list[str] = Field(default_factory=list)
    timeline_start: float = 0.0
    timeline_end: float = 0.0
    description: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── System Metrics ───────────────────────────────────────────────

class SystemMetrics(BaseModel):
    """Pipeline health and performance metrics."""
    timestamp: float = 0.0
    active_flows: int = 0
    total_packets_processed: int = 0
    packets_per_sec: float = 0.0
    alerts_per_min: float = 0.0
    open_incidents: int = 0
    baseline_drift_rejections: int = 0
    ring_buffer_drops: int = 0
    uptime_seconds: float = 0.0

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── API Response Models ─────────────────────────────────────────

class DashboardStats(BaseModel):
    """Aggregated stats for the dashboard header."""
    active_flows: int = 0
    alerts_last_hour: int = 0
    total_alerts: int = 0
    open_incidents: int = 0
    total_incidents: int = 0
    threat_level: str = "Normal"
    packets_processed: int = 0
    uptime: str = "0h 0m"

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class TopTalker(BaseModel):
    """Top source or destination by flow count."""
    ip: str
    flow_count: int
    byte_count: int
    alert_count: int = 0
