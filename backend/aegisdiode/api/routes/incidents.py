"""
AegisDiode Incidents Endpoints
===============================
Query, acknowledge, and export correlated threat incidents.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response
from aegisdiode.db.repository import repository
from aegisdiode.incidents.exporter import IncidentExporter

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])
exporter = IncidentExporter()


@router.get("")
async def list_incidents(
    classification: str = Query(None, description="Filter by classification: Low, Medium, High, Critical"),
    status: str = Query(None, description="Filter by status: ACTIVE, ACKNOWLEDGED, RESOLVED"),
    limit: int = Query(50, ge=1, le=500),
):
    """List correlated incidents."""
    incidents = await repository.get_incidents(
        classification=classification,
        status=status,
        limit=limit,
    )
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Get full details of an incident including timeline and contributing alerts."""
    incident = await repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = await repository.get_alerts_by_ids(incident.alert_ids)
    return {
        "incident": incident,
        "alerts": alerts,
    }


@router.get("/{incident_id}/export")
async def export_incident_report(incident_id: str):
    """Export a self-contained JSON report for air-gapped SOC analysis."""
    incident = await repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = await repository.get_alerts_by_ids(incident.alert_ids)
    json_report = exporter.export_incident_json(incident, alerts)

    filename = f"aegisdiode_incident_{incident_id[:8]}.json"
    return Response(
        content=json_report,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str):
    """Mark an incident as acknowledged by SOC analyst."""
    success = await repository.update_incident_status(incident_id, "ACKNOWLEDGED")
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "acknowledged", "incident_id": incident_id}
