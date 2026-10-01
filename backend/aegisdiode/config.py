"""
AegisDiode Configuration
========================
Centralized configuration for all pipeline components.
"""

from dataclasses import dataclass, field
from pathlib import Path
import os


@dataclass
class CaptureConfig:
    """Packet capture settings."""
    interface: str = "eth0"
    ring_buffer_size: int = 65536  # Number of packets in ring buffer
    bpf_filter: str = ""  # Berkeley Packet Filter expression
    snaplen: int = 1500  # Max bytes to capture per packet


@dataclass
class FlowConfig:
    """Flow keying and timer settings."""
    active_timeout: float = 60.0  # Seconds — flow expires after this idle time
    idle_timeout: float = 15.0  # Seconds — grace period before final expiry
    sweep_interval: float = 5.0  # Seconds — how often to check for expired flows
    max_flows: int = 100000  # Maximum concurrent tracked flows


@dataclass
class FeatureConfig:
    """Feature extraction settings."""
    extraction_window: int = 50  # Packets per extraction window
    min_packets: int = 5  # Minimum packets before feature extraction
    entropy_sample_size: int = 256  # Bytes to sample for entropy
    size_histogram_bins: int = 8  # Bins for packet size distribution


@dataclass
class BaselineConfig:
    """Baseline engine settings."""
    ewma_alpha: float = 0.1  # EWMA smoothing factor
    window_size: int = 100  # Rolling window size (observations)
    drift_threshold: float = 3.0  # MAD-based drift rejection threshold
    min_observations: int = 10  # Minimum observations before baseline is active
    update_interval: float = 10.0  # Seconds between baseline updates


@dataclass
class DetectorConfig:
    """Anomaly detector settings."""
    iat_z_threshold: float = 3.0  # Z-score threshold for IAT anomaly
    size_kl_threshold: float = 2.0  # KL divergence threshold for size anomaly
    entropy_z_threshold: float = 3.0  # Z-score threshold for entropy anomaly
    rate_z_threshold: float = 3.0  # Z-score threshold for rate anomaly
    high_entropy_threshold: float = 7.5  # Shannon entropy — encrypted data
    low_entropy_threshold: float = 1.0  # Shannon entropy — covert channel
    beaconing_cv_threshold: float = 0.05  # IAT CV threshold for beaconing


@dataclass
class CorrelationConfig:
    """Multi-signal correlation settings."""
    correlation_window: float = 30.0  # Seconds — time window for signal fusion
    min_detectors: int = 2  # Minimum distinct detectors for incident creation
    merge_window: float = 60.0  # Seconds — merge overlapping incidents


@dataclass
class ScoringConfig:
    """Threat scoring weights."""
    detector_weights: dict = field(default_factory=lambda: {
        "iat": 0.25,
        "size": 0.20,
        "entropy": 0.30,
        "rate": 0.25,
    })
    severity_weights: dict = field(default_factory=lambda: {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    })
    classification_thresholds: dict = field(default_factory=lambda: {
        "Low": 30,
        "Medium": 60,
        "High": 80,
        "Critical": 100,
    })


@dataclass
class APIConfig:
    """FastAPI server settings."""
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list = field(default_factory=lambda: [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ])


@dataclass
class AegisDiodeConfig:
    """Root configuration for the entire system."""
    # Database
    db_path: str = field(default_factory=lambda: os.environ.get(
        "AEGISDIODE_DB_PATH",
        str(Path(__file__).parent.parent / "data" / "aegisdiode.db")
    ))

    # Sub-configurations
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    flow: FlowConfig = field(default_factory=FlowConfig)
    feature: FeatureConfig = field(default_factory=FeatureConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    api: APIConfig = field(default_factory=APIConfig)

    # Demo mode
    demo_mode: bool = True  # Use simulated traffic instead of live capture


# Global config singleton
config = AegisDiodeConfig()
