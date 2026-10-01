"""
AegisDiode Flows Endpoints
===========================
Query observation flows and feature histories.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from aegisdiode.db.repository import repository

router = APIRouter(prefix="/api/flows", tags=["Flows"])


@router.get("")
async def list_flows(
    state: str = Query(None, description="Filter by state: active, idle, expired"),
    limit: int = Query(50, ge=1, le=500),
):
    """List observation flows."""
    flows = await repository.get_flows(state=state, limit=limit)
    return {"flows": flows, "count": len(flows)}


@router.get("/{flow_id}")
async def get_flow_detail(flow_id: str):
    """Retrieve details for a specific flow."""
    flow = await repository.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    features = await repository.get_flow_features(flow_id)
    return {"flow": flow, "features": features}
