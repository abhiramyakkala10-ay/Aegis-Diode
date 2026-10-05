# AegisDiode — Implementation Plan

> **SIH 2026 | Problem ID: SIH26145 | Team: Hexagonal Hive (172598)**
> AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

---

## Current State

The project has a working **Python prototype** with all 7 pipeline stages implemented:
1. Packet Capture (Scapy-based PCAP replay)
2. Flow Keying (5-tuple + active/idle timers)
3. Feature Extraction (IAT, size stats, Shannon entropy)
4. Baseline Engine (rolling stats + drift-rejection median filter)
5. Anomaly Detection (4 detectors: IAT, size, entropy, flow-rate)
6. Correlation Engine (time-windowed multi-signal fusion + deterministic scoring)
7. Incident Timeline (JSON export)

Backend API (FastAPI + WebSocket) and traffic simulator with 5 attack patterns are functional.
A static HTML dashboard exists but **no React frontend** has been built yet.

---

## Gap Analysis: PPT vs Current Implementation

| PPT Claim | Current Status | Priority |
|---|---|---|
| Go 1.22 + AF_PACKET (TX=0) ingestion | Python + Scapy (demo prototype) | Low — Python demo is acceptable for SIH |
| eBPF/XDP ring buffers | Not implemented | Low — production roadmap item |
| JA4+ Network Fingerprinting | **Missing** — not in any module | **HIGH** |
| Welch FFT Power Spectral Density (C2 beaconing) | **Missing** — IAT detector exists but no FFT | **HIGH** |
| Shannon Entropy | Implemented in `features/entropy.py` | Done |
| STIX 2.1 / JSON-LD incident export | **Missing** — basic JSON export only | **HIGH** |
| MITRE ATT&CK tactic mapping | **Missing** — no tactic IDs in scoring | **HIGH** |
| 6-vector deterministic threat scoring | Partially done in `correlation/scoring.py` | **MEDIUM** |
| Quantized ONNX models | **Missing** | LOW — PPT mentions but not core |
| React 18 SOC Dashboard | **Missing** — only static HTML | **HIGH** |
| Docker + Docker Compose | **Missing** — no Dockerfile/compose | **MEDIUM** |
| Anti-Poison drift-rejection baselines | Implemented in `baselines/drift_reject.py` | Done |
| Flow timers (60s active / 15s idle) | Implemented in `flows/flow_table.py` | Done |
| Zero-Gap Initialization | Implemented in `flows/flow_tracker.py` | Done |
| Multi-signal fusion | Implemented in `correlation/fusion.py` | Done |
| Traffic simulator + attack patterns | Implemented (5 attack types) | Done |
| Validation with CIC-IDS2018 / UNSW-NB15 | **Missing** — no dataset integration | **MEDIUM** |

---

## Implementation Phases

### Phase 1: Critical PPT Features (Backend) — ~3 days

These features are explicitly called out in the PPT and must exist for the demo.

#### 1.1 JA4+ Network Fingerprinting
**File:** `backend/aegisdiode/features/ja4_fingerprint.py`

Implement passive TLS/QUIC fingerprinting from metadata (no payload decryption):
- Extract TLS ClientHello cipher suites, extensions, and supported groups from unencrypted TLS handshake metadata
- Compute JA4+ hash: `(protocol)(version)(SNI)(cipher_count)(extension_count)_(cipher_hash)_(extension_hash)`
- Store fingerprint per flow in the flow table
- Add JA4+ as a feature vector input to the anomaly detector
- Add a `ja4_detector.py` that flags known-malicious JA4+ signatures and unknown fingerprints

**References:** Fox-IT / Althouse 2023 JA4+ specification

#### 1.2 Welch FFT C2 Beaconing Detector
**File:** `backend/aegisdiode/detectors/beacon_detector.py`

Detect periodic C2 callbacks via frequency-domain analysis:
- Collect IAT time series per flow (already extracted by `features/iat.py`)
- Apply Welch's method (`scipy.signal.welch`) to compute Power Spectral Density (PSD)
- Detect dominant frequency peaks: if PSD peak-to-median ratio > threshold → beaconing
- Handle jitter: window PSD peaks within ±10% frequency band
- Output: beacon periodicity estimate (seconds), confidence score

**References:** Welch FFT PSD (IEEE 1967)

#### 1.3 STIX 2.1 / JSON-LD Incident Export
**File:** `backend/aegisdiode/incidents/stix_exporter.py`

Convert incident timelines to OASIS STIX 2.1 Bundles:
- Map each incident to STIX `Indicator` + `ObservedData` + `Sighting` objects
- Include `NetworkTraffic` SCOs (STIX Cyber Observables) for flow data
- Map threat scores to STIX `confidence` field
- Add MITRE ATT&CK tactic references via `ExternalReference` objects
- Output valid JSON-LD with STIX 2.1 `@context` for semantic interoperability
- Add API endpoint: `GET /api/incidents/{id}/stix` and `GET /api/incidents/export/stix`

#### 1.4 MITRE ATT&CK Tactic Mapping
**File:** `backend/aegisdiode/correlation/mitre_mapping.py`

Map detector outputs to MITRE ATT&CK tactics and techniques:
- Port scan → Reconnaissance (TA0043) / Network Service Discovery (T1046)
- Data exfiltration → Exfiltration (TA0010) / Exfiltration Over C2 Channel (T1041)
- DoS flood → Impact (TA0040) / Network Denial of Service (T1498)
- C2 beaconing → Command and Control (TA0011) / Application Layer Protocol (T1071)
- Baseline poisoning attempt → Defense Evasion (TA0005)
- Integrate tactic IDs into scoring engine output and STIX export

#### 1.5 6-Vector Threat Scoring
**File:** Update `backend/aegisdiode/correlation/scoring.py`

Extend the deterministic scoring to a full 6-vector system:
1. IAT anomaly score
2. Size anomaly score
3. Entropy anomaly score
4. Flow-rate anomaly score
5. JA4+ suspicion score (new)
6. Beacon periodicity score (new)

Composite score = weighted sum with configurable weights. All vectors auditable.

---

### Phase 2: React SOC Dashboard — ~3 days

#### 2.1 Frontend Setup
```
frontend/
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── components/
│   │   ├── Dashboard.tsx          # Main SOC layout
│   │   ├── FlowTable.tsx          # Active flows with feature vectors
│   │   ├── ThreatTimeline.tsx     # Correlated incident timeline
│   │   ├── AnomalyChart.tsx       # Real-time anomaly score charts
│   │   ├── BaselineMonitor.tsx    # Drift indicators
│   │   ├── IncidentDetail.tsx     # Single incident drilldown with STIX export
│   │   ├── BeaconAnalysis.tsx     # FFT PSD visualization
│   │   └── StatsBar.tsx           # Top-level KPIs (flows/sec, alerts, uptime)
│   ├── hooks/
│   │   └── useWebSocket.ts       # WebSocket connection to FastAPI
│   └── types/
│       └── index.ts              # TypeScript types matching API models
├── package.json
├── vite.config.ts
├── tsconfig.json
└── index.html
```

**Stack:** React 18 + TypeScript + Vite + Recharts + TailwindCSS

#### 2.2 Dashboard Features
- **Live Flow Monitor:** Table of active observation flows with 5-tuple, packet count, 6-vector scores
- **Threat Timeline:** Visual timeline of correlated incidents (time on x-axis, severity on y-axis)
- **Anomaly Heatmap:** Multi-detector signal matrix (flow × detector) with color-coded severity
- **Baseline Health:** Rolling baseline status with drift-rejection indicators
- **Incident Detail:** Drill-down view with full feature vectors, MITRE ATT&CK tactic, STIX export button
- **Beacon Analysis:** Welch FFT PSD chart for suspected C2 flows
- **Real-time Updates:** WebSocket-driven, no polling

---

### Phase 3: Docker + Infrastructure — ~1 day

#### 3.1 Dockerfiles
- `backend/Dockerfile` — Python 3.11 slim, install requirements, run uvicorn
- `frontend/Dockerfile` — Node 18 build stage → nginx serve static

#### 3.2 Docker Compose
```yaml
services:
  backend:
    build: ./backend
    ports: ["8000:8000"]
    volumes: ["./backend/data:/app/data"]
  frontend:
    build: ./frontend
    ports: ["5173:80"]
    depends_on: [backend]
```

#### 3.3 Demo Data & Validation
- Include sample PCAP files in `sample_data/`
- Add a `scripts/run_demo.sh` that starts the simulator with mixed attacks
- Document CIC-IDS2018 / UNSW-NB15 dataset integration for validation

---

### Phase 4: Polish & Documentation — ~1 day

- Update README.md to match PPT claims exactly
- Write ARCHITECTURE.md with detailed pipeline diagrams
- Add test suite for critical modules (scoring, STIX export, JA4+, beacon detector)
- Performance benchmarks demonstrating throughput metrics
- Record a demo video / screenshots for SOC dashboard

---

## Execution Priority (Speed Optimized)

For fastest SIH-ready delivery, work in this order:

```
Day 1:  [1.1] JA4+ Fingerprinting + [1.2] Welch FFT Beacon Detector
Day 2:  [1.3] STIX 2.1 Export + [1.4] MITRE ATT&CK Mapping + [1.5] 6-Vector Scoring
Day 3:  [2.1] Frontend Setup + [2.2] Dashboard (core views)
Day 4:  [2.2] Dashboard (remaining views + WebSocket integration)
Day 5:  [3.1-3.3] Docker + Sample Data
Day 6:  [Phase 4] Polish, testing, README, demo
```

**Parallel tracks:** Backend features (Phase 1) and Frontend (Phase 2) can be developed simultaneously by splitting work.

---

## Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language for demo | Python (not Go) | Faster development, identical pipeline semantics, acceptable for SIH demo |
| JA4+ implementation | Custom from TLS ClientHello parsing | No maintained Python JA4+ library; specification is public |
| FFT library | `scipy.signal.welch` | Proven, already in the Python ecosystem |
| STIX 2.1 library | `stix2` Python library | Official OASIS library, handles JSON-LD serialization |
| Frontend framework | React 18 + TypeScript | Matches PPT claim, modern SOC dashboard standard |
| Charts | Recharts | Lightweight, React-native, good for real-time data |
| Styling | TailwindCSS | Fast to build SOC-style dark theme dashboard |
