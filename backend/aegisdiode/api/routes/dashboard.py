"""
AegisDiode Dashboard Endpoints
===============================
Provides statistics and top talker analytics for the SOC dashboard.
"""

from __future__ import annotations

from fastapi import APIRouter
from aegisdiode.db.repository import repository

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats():
    """Retrieve overall pipeline and incident statistics."""
    stats = await repository.get_dashboard_stats()
    return stats


@router.get("/top-talkers")
async def get_top_talkers(limit: int = 5):
    """Retrieve top talkers by flow volume."""
    talkers = await repository.get_top_talkers(limit=limit)
    return talkers
