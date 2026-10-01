"""
AegisDiode Simulator API Endpoints
===================================
Allows starting/stopping synthetic traffic simulation and injecting attack patterns for demo.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Body, HTTPException
from aegisdiode.simulator.attack_patterns import ATTACK_GENERATORS

router = APIRouter(prefix="/api/simulator", tags=["Simulator"])

# State references set by main app
_traffic_gen = None


def set_traffic_generator(gen):
    global _traffic_gen
    _traffic_gen = gen


@router.get("/status")
async def get_simulator_status():
    """Get traffic generator status and stats."""
    if not _traffic_gen:
        return {"running": False, "packets_generated": 0, "attacks_injected": 0}
    return _traffic_gen.stats


@router.post("/start")
async def start_simulator(pps: float = Body(50.0, embed=True)):
    """Start background traffic generation."""
    if not _traffic_gen:
        raise HTTPException(status_code=500, detail="Traffic generator not initialized")
    await _traffic_gen.start(packets_per_sec=pps)
    return {"status": "started", "pps": pps}


@router.post("/stop")
async def stop_simulator():
    """Stop background traffic generation."""
    if not _traffic_gen:
        raise HTTPException(status_code=500, detail="Traffic generator not initialized")
    await _traffic_gen.stop()
    return {"status": "stopped"}


@router.post("/inject-attack")
async def inject_attack(attack_type: str = Body(..., embed=True)):
    """Inject a specific attack pattern."""
    if not _traffic_gen:
        raise HTTPException(status_code=500, detail="Traffic generator not initialized")

    if attack_type not in ATTACK_GENERATORS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type '{attack_type}'. Available: {list(ATTACK_GENERATORS.keys())}",
        )

    res = await _traffic_gen.inject_attack(attack_type)
    return res
