# AegisDiode — Agent Guide

> Technical reference for contributors and AI agents working on this codebase.

---

## Project Identity

| Field | Value |
|---|---|
| **Project** | AegisDiode — Passive Threat Correlation for Unidirectional Networks |
| **Problem** | SIH 2026, ID SIH26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic |
| **Theme** | Blockchain & Cybersecurity |
| **Team** | Hexagonal Hive (ID: 172598) |
| **Category** | Software |

---

## Architecture Overview

AegisDiode is a **7-stage passive ingestion pipeline** that detects cyber threats in unidirectional IP traffic (data diode networks) without requiring a return path.

```
Packet Capture → Flow Keying → Feature Extraction → Baseline Engine
    → Anomaly Detection → Correlation/Fusion → Incident Timeline
```

### Core Constraint: TX=0

The entire system operates in **receive-only mode**. No packets are ever transmitted. This is a fundamental design constraint — every module must work passively. Never add code that sends network traffic.

### Zero-Gap Initialization

Traditional IDS requires SYN/ACK handshakes. AegisDiode initializes tracking on the **first observed packet**, using bounded observation windows instead of connection state.

---

## Project Structure

```
backend/
├── aegisdiode/
│   ├── config.py                 # Global configuration constants
│   ├── capture/                  # Stage 1: Packet ingestion
│   │   ├── packet_reader.py      # PCAP reader / live capture
│   │   └── ring_buffer.py        # Circular ring buffer (AF_PACKET simulation)
│   ├── flows/                    # Stage 2: Flow keying
│   │   ├── flow_tracker.py       # 5-tuple flow tracking + zero-gap init
│   │   └── flow_table.py         # Active/idle timer management (60s/15s)
│   ├── features/                 # Stage 3: Feature extraction
│   │   ├── iat.py                # Inter-Arrival Time analysis
│   │   ├── size_stats.py         # Packet size distribution
│   │   ├── entropy.py            # Shannon entropy computation
│   │   └── ja4_fingerprint.py    # [TODO] JA4+ passive TLS fingerprinting
│   ├── baselines/                # Stage 4: Anti-poison baselines
│   │   ├── rolling_stats.py      # Rolling statistical baselines
│   │   └── drift_reject.py       # Drift-rejection median filter
│   ├── detectors/                # Stage 5: Anomaly detection
│   │   ├── iat_detector.py       # IAT anomaly (timing patterns)
│   │   ├── size_detector.py      # Size anomaly (unusual packet sizes)
│   │   ├── entropy_detector.py   # Entropy anomaly (encrypted/compressed payloads)
│   │   ├── rate_detector.py      # Flow-rate anomaly (volumetric)
│   │   └── beacon_detector.py    # [TODO] Welch FFT C2 beaconing detector
│   ├── correlation/              # Stage 6: Multi-signal fusion
│   │   ├── fusion.py             # Time-windowed signal fusion
│   │   ├── scoring.py            # 6-vector deterministic threat scoring
│   │   └── mitre_mapping.py      # [TODO] MITRE ATT&CK tactic mapping
│   ├── incidents/                # Stage 7: Incident timeline
│   │   ├── timeline.py           # Incident timeline builder
│   │   ├── exporter.py           # JSON report exporter
│   │   └── stix_exporter.py      # [TODO] STIX 2.1 / JSON-LD export
│   ├── db/                       # Persistence
│   │   ├── init.py               # Schema initialization
│   │   ├── models.py             # SQLite data models
│   │   └── repository.py         # Data access layer
│   ├── api/                      # FastAPI server
│   │   ├── main.py               # App entry + CORS + lifespan
│   │   ├── websocket.py          # Real-time WebSocket handler
│   │   └── routes/
│   │       ├── flows.py          # Flow CRUD endpoints
│   │       ├── alerts.py         # Alert endpoints
│   │       ├── incidents.py      # Incident endpoints
│   │       ├── dashboard.py      # Dashboard aggregate stats
│   │       └── simulator.py      # Traffic simulator controls
│   └── simulator/                # Demo traffic generator
│       ├── traffic_gen.py        # Synthetic traffic generator
│       └── attack_patterns.py    # Attack pattern templates (5 types)
├── data/
│   └── aegisdiode.db             # SQLite database
├── requirements.txt
└── Dockerfile                    # [TODO]

frontend/                         # [TODO] React 18 + TypeScript
├── src/
│   ├── components/               # SOC dashboard views
│   ├── hooks/                    # WebSocket hooks
│   └── types/                    # API type definitions
├── package.json
└── vite.config.ts
```

---

## Key Technical Concepts

### 5-Tuple Flow Keying
Flows are identified by `(src_ip, dst_ip, src_port, dst_port, protocol)`. Since traffic is unidirectional, there is no reverse tuple. Active timer: 60s. Idle timer: 15s. Windows span micro (100ms) to macro (60s).

### 6-Vector Threat Scoring
Each flow is scored on 6 independent dimensions:
1. **IAT anomaly** — timing irregularity vs baseline
2. **Size anomaly** — packet size distribution deviation
3. **Entropy anomaly** — Shannon entropy deviation (DGA, encrypted exfil)
4. **Flow-rate anomaly** — volumetric deviation (DoS, scan)
5. **JA4+ suspicion** — unknown or malicious TLS fingerprint
6. **Beacon periodicity** — Welch FFT dominant frequency strength

Composite score is a weighted sum. All vectors are individually auditable.

### Drift-Rejection Baselines
Baselines use a rolling median with drift-rejection: if an incoming sample deviates more than `k * MAD` (median absolute deviation) from the current baseline, it is rejected from the update. This prevents slow-poisoning attacks from shifting baselines.

### Multi-Signal Fusion
Individual detector alerts are fused using time-windowed correlation. Multiple detectors firing within the same time window on the same flow (or related flows) are merged into a single incident with elevated severity.

### STIX 2.1 / JSON-LD Export
Incidents export as OASIS STIX 2.1 bundles containing:
- `Indicator` — the threat pattern detected
- `ObservedData` — raw observation (flow features)
- `Sighting` — when/where the indicator was seen
- `NetworkTraffic` SCO — flow-level details
- `ExternalReference` — MITRE ATT&CK tactic/technique IDs

### MITRE ATT&CK Mapping
| Detection Pattern | Tactic | Technique |
|---|---|---|
| Port scan | Reconnaissance (TA0043) | Network Service Discovery (T1046) |
| Data exfiltration | Exfiltration (TA0010) | Exfil Over C2 Channel (T1041) |
| DoS flood | Impact (TA0040) | Network Denial of Service (T1498) |
| C2 beaconing | Command & Control (TA0011) | Application Layer Protocol (T1071) |
| Baseline poisoning | Defense Evasion (TA0005) | Indicator Removal (T1070) |

---

## Development Commands

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m aegisdiode.db.init                                    # Init database
uvicorn aegisdiode.api.main:app --host 0.0.0.0 --port 8000 --reload

# Traffic simulator
python -m aegisdiode.simulator.traffic_gen --mode mixed --duration 300
python -m aegisdiode.simulator.traffic_gen --attack beaconing

# Frontend (once built)
cd frontend
npm install && npm run dev

# Docker
docker-compose up --build
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/flows` | List active observation flows |
| GET | `/api/flows/{id}` | Flow detail with feature vectors |
| GET | `/api/alerts` | List anomaly alerts |
| GET | `/api/incidents` | List correlated incidents |
| GET | `/api/incidents/{id}` | Incident detail with timeline |
| GET | `/api/incidents/{id}/stix` | STIX 2.1 export (TODO) |
| GET | `/api/dashboard/stats` | Aggregate dashboard statistics |
| POST | `/api/simulator/start` | Start traffic simulator |
| POST | `/api/simulator/stop` | Stop traffic simulator |
| WS | `/ws/live` | Real-time flow/alert/incident stream |

---

## Coding Conventions

- **Python:** PEP 8, type hints on all function signatures, no wildcard imports
- **Naming:** modules are `snake_case`, classes are `PascalCase`
- **Config:** all tunable parameters in `config.py`, never hardcode thresholds
- **Database:** all SQL in `db/repository.py`, never raw SQL in pipeline modules
- **Testing:** tests mirror source structure in `backend/tests/`
- **No TX:** never import or use any network-sending capability; the system is receive-only

---

## References

| Standard | Usage |
|---|---|
| NIST SP 800-82 Rev. 3 | Unidirectional data diode architecture |
| Linux AF_PACKET / eBPF XDP | Zero-copy ring buffer interface (prod target) |
| OASIS STIX 2.1 | Incident export schema |
| MITRE ATT&CK | Tactic/technique classification |
| JA4+ (Fox-IT / Althouse 2023) | Passive TLS/QUIC fingerprinting |
| Welch FFT PSD (IEEE 1967) | C2 beaconing frequency detection |
| CIC-IDS2018 | Validation dataset (volumetric DDoS, DGA) |
| UNSW-NB15 | Validation dataset (entropy, exfiltration ratios) |
