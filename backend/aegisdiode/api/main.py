"""
AegisDiode Main Application Server
====================================
FastAPI application mounting REST routes, WebSocket broadcaster, static SOC dashboard,
and running the full asynchronous passive threat correlation engine.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from aegisdiode.config import config
from aegisdiode.db.init import init_db
from aegisdiode.db.repository import repository
from aegisdiode.capture.packet_reader import SyntheticPacketSource
from aegisdiode.flows.flow_tracker import FlowTracker
from aegisdiode.flows.flow_table import FlowTable
from aegisdiode.features import FeatureExtractor
from aegisdiode.baselines.rolling_stats import BaselineManager
from aegisdiode.baselines.drift_reject import DriftRejectionFilter
from aegisdiode.detectors.iat_detector import IatDetector
from aegisdiode.detectors.size_detector import SizeDetector
from aegisdiode.detectors.entropy_detector import EntropyDetector
from aegisdiode.detectors.rate_detector import RateDetector
from aegisdiode.correlation.fusion import FusionEngine
from aegisdiode.simulator.traffic_gen import TrafficGenerator

from aegisdiode.api.websocket import ws_manager
from aegisdiode.api.routes import dashboard, flows, alerts, incidents, simulator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("aegisdiode")

# Global engine components
packet_source = SyntheticPacketSource()
traffic_gen = TrafficGenerator(packet_source)
flow_tracker = FlowTracker()
flow_table = FlowTable(flow_tracker)
feature_extractor = FeatureExtractor()
baseline_manager = BaselineManager()
fusion_engine = FusionEngine()

# Initialize anomaly detectors
detectors = [
    IatDetector(),
    SizeDetector(),
    EntropyDetector(),
    RateDetector(),
]

# Background tasks
_pipeline_task: asyncio.Task | None = None
_telemetry_task: asyncio.Task | None = None


async def pipeline_loop():
    """Main packet processing & threat correlation pipeline loop."""
    logger.info("Pipeline processing loop started.")
    packet_gen = packet_source.read_packets()

    async for packet in packet_gen:
        try:
            # 1. Process packet through flow tracker
            flow = await flow_tracker.process_packet(packet)
            await flow_table.touch_flow(flow)
            await repository.upsert_flow(flow)

            # 2. Extract features if window threshold reached
            features = feature_extractor.extract_features(flow)
            if features:
                await repository.insert_flow_features(features)
                flow_key_str = f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}"

                # 3. Get or update baseline
                baseline = await baseline_manager.get_baseline(flow_key_str)
                
                # 4. Evaluate each detector
                new_alerts = []
                if baseline:
                    for detector in detectors:
                        alert = detector.evaluate(features, baseline)
                        if alert:
                            alert_id = await repository.insert_alert(alert)
                            alert.id = alert_id
                            new_alerts.append(alert)
                            # Broadcast single-detector alert
                            await ws_manager.broadcast({
                                "type": "alert_fired",
                                "alert": alert.to_dict(),
                            })

                # Update baseline with drift rejection check
                await baseline_manager.update_baseline(flow_key_str, features)

                # 5. Multi-signal correlation fusion
                if new_alerts:
                    for alert in new_alerts:
                        incident = await fusion_engine.process_alert(alert)
                        if incident:
                            incident_id = await repository.insert_incident(incident)
                            incident.id = incident_id
                            # Broadcast correlated incident
                            await ws_manager.broadcast({
                                "type": "incident_created",
                                "incident": incident.to_dict(),
                            })

        except Exception as e:
            logger.error(f"Error in pipeline loop: {e}", exc_info=True)


async def telemetry_broadcast_loop():
    """Periodically broadcasts metrics and flow updates over WebSockets."""
    logger.info("Telemetry broadcast loop started.")
    total_pkts_prev = 0
    t_prev = time.time()

    while True:
        try:
            await asyncio.sleep(1.0)
            t_now = time.time()
            dt = t_now - t_prev

            stats = await repository.get_dashboard_stats()
            gen_stats = traffic_gen.stats
            pkts_curr = gen_stats.get("packets_generated", 0)
            pps = int((pkts_curr - total_pkts_prev) / max(dt, 0.1))

            total_pkts_prev = pkts_curr
            t_prev = t_now

            # Broadcast metrics tick
            await ws_manager.broadcast({
                "type": "metrics_tick",
                "active_flows": flow_tracker.active_count,
                "pps": pps,
                "total_packets": pkts_curr,
                "total_alerts": stats.get("total_alerts", 0),
                "total_incidents": stats.get("total_incidents", 0),
                "recent_alerts": stats.get("alerts_last_5m", 0),
            })

            # Every 3 seconds, broadcast flow table update
            if int(t_now) % 3 == 0:
                active_flows = await repository.get_flows(state="active", limit=15)
                await ws_manager.broadcast({
                    "type": "flows_update",
                    "flows": active_flows,
                })

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in telemetry loop: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Initializing AegisDiode database...")
    await init_db()
    await repository.connect()

    # Pass traffic generator reference to simulator router
    simulator.set_traffic_generator(traffic_gen)

    # Start background tasks
    global _pipeline_task, _telemetry_task
    _pipeline_task = asyncio.create_task(pipeline_loop())
    _telemetry_task = asyncio.create_task(telemetry_broadcast_loop())

    # Start initial demo traffic
    await traffic_gen.start(packets_per_sec=50.0)

    yield

    logger.info("Shutting down AegisDiode background services...")
    await traffic_gen.stop()
    packet_source.stop()
    await repository.close()

    if _pipeline_task:
        _pipeline_task.cancel()
    if _telemetry_task:
        _telemetry_task.cancel()


app = FastAPI(
    title="AegisDiode Threat Correlation Engine",
    description="Passive Threat Correlation Engine for Unidirectional Networks (SIH26145)",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(dashboard.router)
app.include_router(flows.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(simulator.router)

# WebSocket endpoint
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        ws_manager.disconnect(websocket)


# Mount static directory for Web SOC Dashboard
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(static_dir / "index.html")

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    uvicorn.run("aegisdiode.api.main:app", host=config.api.host, port=config.api.port, reload=True)
