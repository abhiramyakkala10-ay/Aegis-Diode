"""
AegisDiode Alerts Endpoints
============================
Query single-detector anomaly alerts.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from aegisdiode.db.repository import repository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    detector_type: str = Query(None, description="Filter by detector: iat, size, entropy, rate"),
    severity: str = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH"),
    limit: int = Query(50, ge=1, le=500),
):
    """List anomaly alerts."""
    alerts = await repository.get_alerts(
        detector_type=detector_type,
        severity=severity,
        limit=limit,
    )
    return {"alerts": alerts, "count": len(alerts)}
