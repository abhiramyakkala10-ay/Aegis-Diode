"""
AegisDiode Database Initialization
===================================
Creates SQLite schema with WAL mode for the pipeline.
"""

import asyncio
import aiosqlite
from pathlib import Path

from aegisdiode.config import config


SCHEMA_SQL = """
-- Enable WAL mode for better concurrent read performance
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Observation Flows
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_state ON flows(state);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);

-- Flow Features (per extraction window)
CREATE TABLE IF NOT EXISTS flow_features (
    id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    -- IAT features
    iat_mean REAL DEFAULT 0, iat_std REAL DEFAULT 0,
    iat_min REAL DEFAULT 0, iat_max REAL DEFAULT 0,
    iat_median REAL DEFAULT 0, iat_cv REAL DEFAULT 0,
    -- Size features
    size_mean REAL DEFAULT 0, size_std REAL DEFAULT 0,
    size_min REAL DEFAULT 0, size_max REAL DEFAULT 0,
    bytes_per_sec REAL DEFAULT 0, size_histogram TEXT DEFAULT '[]',
    -- Entropy features
    entropy_value REAL DEFAULT 0, entropy_change_rate REAL DEFAULT 0,
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);

CREATE INDEX IF NOT EXISTS idx_features_flow ON flow_features(flow_id);
CREATE INDEX IF NOT EXISTS idx_features_ts ON flow_features(timestamp);

-- Baselines
CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    pattern_key TEXT UNIQUE NOT NULL,
    observation_count INTEGER DEFAULT 0,
    last_updated REAL DEFAULT 0,
    iat_median REAL DEFAULT 0, iat_mad REAL DEFAULT 1,
    size_median REAL DEFAULT 0, size_mad REAL DEFAULT 1,
    entropy_median REAL DEFAULT 0, entropy_mad REAL DEFAULT 1,
    rate_median REAL DEFAULT 0, rate_mad REAL DEFAULT 1,
    drift_rejected_count INTEGER DEFAULT 0,
    last_drift_event REAL
);

CREATE INDEX IF NOT EXISTS idx_baselines_pattern ON baselines(pattern_key);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL,
    flow_key_str TEXT DEFAULT '',
    detector_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL DEFAULT 0,
    z_score REAL DEFAULT 0,
    description TEXT DEFAULT '',
    feature_values TEXT DEFAULT '{}',
    baseline_values TEXT DEFAULT '{}',
    timestamp REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_flow ON alerts(flow_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts(detector_type);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    alert_ids TEXT DEFAULT '[]',
    detector_types TEXT DEFAULT '[]',
    threat_score REAL DEFAULT 0,
    classification TEXT DEFAULT 'Low',
    status TEXT DEFAULT 'open',
    target_ip TEXT DEFAULT '',
    source_ips TEXT DEFAULT '[]',
    affected_flow_ids TEXT DEFAULT '[]',
    timeline_start REAL DEFAULT 0,
    timeline_end REAL DEFAULT 0,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    acknowledged_at TEXT,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(threat_score);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timeline_start);

-- System Metrics
CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    active_flows INTEGER DEFAULT 0,
    total_packets_processed INTEGER DEFAULT 0,
    packets_per_sec REAL DEFAULT 0,
    alerts_per_min REAL DEFAULT 0,
    open_incidents INTEGER DEFAULT 0,
    baseline_drift_rejections INTEGER DEFAULT 0,
    ring_buffer_drops INTEGER DEFAULT 0,
    uptime_seconds REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_metrics_ts ON system_metrics(timestamp);
"""


async def init_database(db_path: str | None = None) -> None:
    """Initialize the SQLite database with the AegisDiode schema."""
    path = db_path or config.db_path
    db_dir = Path(path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(path) as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()
    print(f"[AegisDiode] Database initialized at: {path}")


# Alias for convenience
init_db = init_database


async def get_db(db_path: str | None = None) -> aiosqlite.Connection:
    """Get an async database connection."""
    path = db_path or config.db_path
    db = await aiosqlite.connect(path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


if __name__ == "__main__":
    asyncio.run(init_database())
