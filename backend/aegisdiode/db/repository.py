"""
AegisDiode Data Repository
===========================
Async data access layer for all CRUD operations on the SQLite database.
"""

from __future__ import annotations

import json
import time
from typing import Optional

import aiosqlite

from aegisdiode.config import config
from aegisdiode.db.init import get_db
from aegisdiode.db.models import (
    Alert, BaselineRecord, DashboardStats, FlowFeatures,
    Incident, IncidentStatus, ObservationFlow, SystemMetrics, TopTalker,
)


class Repository:
    """Async data access layer for AegisDiode."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or config.db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self._db = await get_db(self.db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    @property
    def db(self) -> aiosqlite.Connection:
        if not self._db:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._db

    # ─── Flows ────────────────────────────────────────────────────

    async def upsert_flow(self, flow: ObservationFlow) -> None:
        await self.db.execute(
            """INSERT INTO flows (id, src_ip, dst_ip, src_port, dst_port, protocol,
                                  state, first_seen, last_seen, packet_count, byte_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   state=excluded.state, last_seen=excluded.last_seen,
                   packet_count=excluded.packet_count, byte_count=excluded.byte_count""",
            (flow.id, flow.flow_key.src_ip, flow.flow_key.dst_ip,
             flow.flow_key.src_port, flow.flow_key.dst_port, flow.flow_key.protocol,
             flow.state.value, flow.first_seen, flow.last_seen,
             flow.packet_count, flow.byte_count),
        )
        await self.db.commit()

    async def get_flows(self, state: str | None = None, limit: int = 100,
                        offset: int = 0) -> list[dict]:
        query = "SELECT * FROM flows"
        params: list = []
        if state:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self.db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_flow(self, flow_id: str) -> dict | None:
        cursor = await self.db.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_active_flow_count(self) -> int:
        cursor = await self.db.execute(
            "SELECT COUNT(*) FROM flows WHERE state = 'active'")
        row = await cursor.fetchone()
        return row[0] if row else 0

    # ─── Features ─────────────────────────────────────────────────

    async def insert_features(self, features: FlowFeatures) -> None:
        await self.db.execute(
            """INSERT INTO flow_features (id, flow_id, timestamp, packet_count,
                iat_mean, iat_std, iat_min, iat_max, iat_median, iat_cv,
                size_mean, size_std, size_min, size_max, bytes_per_sec, size_histogram,
                entropy_value, entropy_change_rate)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (features.id, features.flow_id, features.timestamp, features.packet_count,
             features.iat.mean, features.iat.std, features.iat.min, features.iat.max,
             features.iat.median, features.iat.cv,
             features.size.mean, features.size.std, features.size.min, features.size.max,
             features.size.bytes_per_sec, json.dumps(features.size.histogram),
             features.entropy.value, features.entropy.change_rate),
        )
        await self.db.commit()

    async def get_flow_features(self, flow_id: str, limit: int = 50) -> list[dict]:
        cursor = await self.db.execute(
            "SELECT * FROM flow_features WHERE flow_id = ? ORDER BY timestamp DESC LIMIT ?",
            (flow_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ─── Baselines ────────────────────────────────────────────────

    async def upsert_baseline(self, baseline: BaselineRecord) -> None:
        await self.db.execute(
            """INSERT INTO baselines (id, pattern_key, observation_count, last_updated,
                iat_median, iat_mad, size_median, size_mad,
                entropy_median, entropy_mad, rate_median, rate_mad,
                drift_rejected_count, last_drift_event)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(pattern_key) DO UPDATE SET
                   observation_count=excluded.observation_count,
                   last_updated=excluded.last_updated,
                   iat_median=excluded.iat_median, iat_mad=excluded.iat_mad,
                   size_median=excluded.size_median, size_mad=excluded.size_mad,
                   entropy_median=excluded.entropy_median, entropy_mad=excluded.entropy_mad,
                   rate_median=excluded.rate_median, rate_mad=excluded.rate_mad,
                   drift_rejected_count=excluded.drift_rejected_count,
                   last_drift_event=excluded.last_drift_event""",
            (baseline.id, baseline.pattern_key, baseline.observation_count,
             baseline.last_updated,
             baseline.iat_median, baseline.iat_mad,
             baseline.size_median, baseline.size_mad,
             baseline.entropy_median, baseline.entropy_mad,
             baseline.rate_median, baseline.rate_mad,
             baseline.drift_rejected_count, baseline.last_drift_event),
        )
        await self.db.commit()

    async def get_baseline(self, pattern_key: str) -> dict | None:
        cursor = await self.db.execute(
            "SELECT * FROM baselines WHERE pattern_key = ?", (pattern_key,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ─── Alerts ───────────────────────────────────────────────────

    async def insert_alert(self, alert: Alert) -> None:
        await self.db.execute(
            """INSERT INTO alerts (id, flow_id, flow_key_str, detector_type, severity,
                confidence, z_score, description, feature_values, baseline_values, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert.id, alert.flow_id, alert.flow_key_str,
             alert.detector_type.value, alert.severity.value,
             alert.confidence, alert.z_score, alert.description,
             json.dumps(alert.feature_values), json.dumps(alert.baseline_values),
             alert.timestamp),
        )
        await self.db.commit()

    async def get_alerts(self, severity: str | None = None,
                         detector: str | None = None,
                         since: float | None = None,
                         limit: int = 100) -> list[dict]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if detector:
            query += " AND detector_type = ?"
            params.append(detector)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = await self.db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_alert(self, alert_id: str) -> dict | None:
        cursor = await self.db.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_alerts_in_window(self, start: float, end: float) -> list[dict]:
        cursor = await self.db.execute(
            "SELECT * FROM alerts WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp",
            (start, end),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_alert_count_since(self, since: float) -> int:
        cursor = await self.db.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (since,))
        row = await cursor.fetchone()
        return row[0] if row else 0

    # ─── Incidents ────────────────────────────────────────────────

    async def insert_incident(self, incident: Incident) -> None:
        await self.db.execute(
            """INSERT INTO incidents (id, alert_ids, detector_types, threat_score,
                classification, status, target_ip, source_ips, affected_flow_ids,
                timeline_start, timeline_end, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident.id, json.dumps(incident.alert_ids),
             json.dumps(incident.detector_types), incident.threat_score,
             incident.classification.value, incident.status.value,
             incident.target_ip, json.dumps(incident.source_ips),
             json.dumps(incident.affected_flow_ids),
             incident.timeline_start, incident.timeline_end, incident.description),
        )
        await self.db.commit()

    async def get_incidents(self, status: str | None = None,
                            limit: int = 50) -> list[dict]:
        query = "SELECT * FROM incidents"
        params: list = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY timeline_start DESC LIMIT ?"
        params.append(limit)

        cursor = await self.db.execute(query, params)
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["alert_ids"] = json.loads(d.get("alert_ids", "[]"))
            d["detector_types"] = json.loads(d.get("detector_types", "[]"))
            d["source_ips"] = json.loads(d.get("source_ips", "[]"))
            d["affected_flow_ids"] = json.loads(d.get("affected_flow_ids", "[]"))
            result.append(d)
        return result

    async def get_incident(self, incident_id: str) -> dict | None:
        cursor = await self.db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["alert_ids"] = json.loads(d.get("alert_ids", "[]"))
        d["detector_types"] = json.loads(d.get("detector_types", "[]"))
        d["source_ips"] = json.loads(d.get("source_ips", "[]"))
        d["affected_flow_ids"] = json.loads(d.get("affected_flow_ids", "[]"))
        return d

    async def acknowledge_incident(self, incident_id: str) -> None:
        await self.db.execute(
            "UPDATE incidents SET status = ?, acknowledged_at = datetime('now') WHERE id = ?",
            (IncidentStatus.ACKNOWLEDGED.value, incident_id),
        )
        await self.db.commit()

    async def get_open_incident_count(self) -> int:
        cursor = await self.db.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        row = await cursor.fetchone()
        return row[0] if row else 0

    # ─── Metrics ──────────────────────────────────────────────────

    async def insert_metrics(self, metrics: SystemMetrics) -> None:
        await self.db.execute(
            """INSERT INTO system_metrics (timestamp, active_flows, total_packets_processed,
                packets_per_sec, alerts_per_min, open_incidents,
                baseline_drift_rejections, ring_buffer_drops, uptime_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (metrics.timestamp, metrics.active_flows, metrics.total_packets_processed,
             metrics.packets_per_sec, metrics.alerts_per_min, metrics.open_incidents,
             metrics.baseline_drift_rejections, metrics.ring_buffer_drops,
             metrics.uptime_seconds),
        )
        await self.db.commit()

    # ─── Dashboard Aggregates ─────────────────────────────────────

    async def get_dashboard_stats(self) -> DashboardStats:
        active = await self.get_active_flow_count()
        alerts_hour = await self.get_alert_count_since(time.time() - 3600)
        incidents = await self.get_open_incident_count()

        cursor = await self.db.execute(
            "SELECT SUM(packet_count) FROM flows")
        row = await cursor.fetchone()
        total_packets = row[0] if row and row[0] else 0

        # Determine threat level
        if incidents >= 5:
            threat_level = "Critical"
        elif incidents >= 3:
            threat_level = "High"
        elif incidents >= 1:
            threat_level = "Medium"
        else:
            threat_level = "Normal"

        return DashboardStats(
            active_flows=active,
            alerts_last_hour=alerts_hour,
            open_incidents=incidents,
            threat_level=threat_level,
            packets_processed=total_packets,
        )

    async def get_top_talkers(self, limit: int = 10) -> list[dict]:
        cursor = await self.db.execute(
            """SELECT dst_ip as ip, COUNT(*) as flow_count, SUM(byte_count) as byte_count
               FROM flows GROUP BY dst_ip ORDER BY flow_count DESC LIMIT ?""",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # Alias methods for API routes
    get_flow_by_id = get_flow
    insert_flow_features = insert_features
    get_incident_by_id = get_incident

    async def get_alerts_by_ids(self, alert_ids: list[str]) -> list[dict]:
        if not alert_ids:
            return []
        placeholders = ",".join(["?"] * len(alert_ids))
        cursor = await self.db.execute(
            f"SELECT * FROM alerts WHERE id IN ({placeholders})", alert_ids
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_incident_status(self, incident_id: str, status: str) -> bool:
        cursor = await self.db.execute(
            "UPDATE incidents SET status = ?, acknowledged_at = datetime('now') WHERE id = ?",
            (status, incident_id),
        )
        await self.db.commit()
        return cursor.rowcount > 0


# Global singleton instance
repository = Repository()
