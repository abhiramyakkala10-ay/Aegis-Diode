
<p align="center">
  <img src="docs/assets/aegisdiode-logo.svg" alt="AegisDiode Logo" width="120" />
</p>

<h1 align="center">AegisDiode</h1>

<p align="center">
  <strong>Passive Threat Correlation for Unidirectional Networks</strong><br/>
  <em>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#features">Features</a> •
  <a href="#demo">Demo</a> •
  <a href="#deployment">Deployment</a>
</p>

---

## 🎯 Problem Statement

> **SIH 2025 — Problem Statement ID: SIH26145**
> *Theme: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*
> **Team: Hexagonal Hive**

Traditional network security tools (IDS/IPS, firewalls) rely on **bidirectional TCP handshakes** and **conversation state** to detect threats. In **unidirectional networks** (data diodes) used by critical infrastructure (power grids, defense, NTRO), there is **no return path** — making conventional tools useless.

**AegisDiode** solves this by shifting from conversation-state analysis to **Observable Behavioral Evidence**, enabling passive threat detection without breaking physical diode isolation.

---

## ✨ Features

### Core Innovations

| Feature | Description |
|---|---|
| **🔒 Zero-Trust Hardware Safety** | Software-enforced receive-only engine (`TX=0`) guarantees physical unidirectional security |
| **🔄 Observation Flow Keying** | Groups unidirectional traffic using **5-Tuple + Time Windows** (60s active / 15s idle) |
| **📊 Statistical Feature Extraction** | Measures **Inter-Arrival Time (IAT)**, packet sizes, and **Shannon Entropy** directly from metadata |
| **🛡️ Anti-Poison Baselines** | Rolling statistical filters with **drift-rejection median** updates prevent baseline manipulation |
| **🔗 Multi-Signal Fusion** | Fuses isolated anomalies into **correlated incident timelines** — eliminates alert fatigue |
| **📋 Auditable Threat Scoring** | Deterministic scoring logic exports compact **JSON incident reports** for offline SOC analysis |
| **⚡ Zero Gap Initialization** | Initializes tracking on the **first seen packet**, bypassing missing SYN/ACK handshakes |

### Paradigm Shift

```
Traditional IDS:  Conversation State  →  Requires bidirectional traffic  →  ❌ Fails on data diodes
AegisDiode:       Observable Behavior  →  Works with receive-only traffic →  ✅ Designed for data diodes
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEGISDIODE PIPELINE                          │
│                                                                 │
│  ┌──────────────────┐                                          │
│  │ Raw Unidirectional│                                          │
│  │     Traffic       │                                          │
│  └────────┬─────────┘                                          │
│           ▼                                                     │
│  ┌──────────────────┐    ┌─────────────────────────────────┐   │
│  │  AF_PACKET Ring   │    │  TECH STACK                     │   │
│  │  Buffer (TX=0)    │    │                                 │   │
│  └────────┬─────────┘    │  Ingestion:  Python + Scapy     │   │
│           ▼              │  Analytics:  NumPy, Pandas       │   │
│  ┌──────────────────┐    │  Database:   SQLite              │   │
│  │  Flow Keying:     │    │  API:        FastAPI + WebSocket │   │
│  │  5-Tuple + Timers │    │  Dashboard:  React 18           │   │
│  └────────┬─────────┘    │  Deploy:     Docker Compose      │   │
│           ▼              │                                 │   │
│  ┌──────────────────┐    └─────────────────────────────────┘   │
│  │ Feature Extraction│                                          │
│  │ IAT·Sizes·Entropy │                                          │
│  └────────┬─────────┘                                          │
│           ▼                                                     │
│  ┌──────────────────┐                                          │
│  │  Multi-Signal     │                                          │
│  │  Correlation      │                                          │
│  └────────┬─────────┘                                          │
│           ▼                                                     │
│  ┌──────────────────┐                                          │
│  │ Incident Timeline │                                          │
│  │  (JSON Export)    │                                          │
│  └──────────────────┘                                          │
└─────────────────────────────────────────────────────────────────┘
```

### Pipeline Stages

1. **Packet Capture** — Ingests raw unidirectional packets via receive-only socket (simulated via PCAP replay in demo mode)
2. **Flow Keying** — Groups packets into observation flows using `(src_ip, dst_ip, src_port, dst_port, protocol)` + active/idle timers
3. **Feature Extraction** — Computes per-flow statistics: IAT distribution, packet size histogram, Shannon entropy of payload bytes
4. **Baseline Engine** — Maintains rolling statistical baselines with drift-rejection to prevent slow poisoning attacks
5. **Anomaly Detection** — Multi-detector system: IAT anomaly, size anomaly, entropy anomaly, flow-rate anomaly
6. **Correlation Engine** — Fuses individual detector alerts using time-windowed multi-signal fusion
7. **Incident Timeline** — Produces actionable, auditable JSON reports for SOC analysts

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Ingestion Engine** | Python 3.11 + Scapy | Packet capture & parsing (demo uses PCAP replay) |
| **Analytics & Baselines** | NumPy, Pandas, SciPy | Statistical feature extraction & anomaly detection |
| **Data Persistence** | SQLite | Lightweight embedded database for flows, alerts, baselines |
| **API Server** | FastAPI + WebSockets | Real-time SOC interface with REST + streaming |
| **Dashboard** | React 18 + Recharts | Real-time threat visualization & incident management |
| **Deployment** | Docker + Docker Compose | Single-command deployment on commodity hardware |

> **Note on Go**: The production architecture specifies Go 1.22 + AF_PACKET for the ingestion engine. This demo prototype uses Python + Scapy for faster development while maintaining identical pipeline semantics.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ & npm
- Docker & Docker Compose (optional, for containerized deployment)

### Option 1: Local Development

```bash
# Clone the repository
git clone https://github.com/hexagonal-hive/aegisdiode.git
cd aegisdiode

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize the database
python -m aegisdiode.db.init

# Start the API server (includes packet processing pipeline)
uvicorn aegisdiode.api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### Option 2: Docker Compose

```bash
docker-compose up --build
```

Access the dashboard at: **http://localhost:5173**
API documentation at: **http://localhost:8000/docs**

---

## 🎮 Demo

The demo prototype includes a **traffic simulator** that generates realistic unidirectional network traffic with injected attack patterns:

```bash
# Run the traffic simulator with attack injection
python -m aegisdiode.simulator.traffic_gen --mode mixed --duration 300

# Available attack scenarios:
#   --attack port_scan      Port scanning pattern
#   --attack data_exfil     Data exfiltration (unusual entropy)
#   --attack dos_flood       Volumetric DoS pattern
#   --attack slow_poison     Gradual baseline poisoning attempt
#   --attack beaconing       C2 beaconing pattern (periodic callbacks)
```

### Demo Scenarios

| Scenario | What It Shows |
|---|---|
| **Port Scan Detection** | Flow-rate anomaly detector fires, correlated with IAT anomaly |
| **Data Exfiltration** | Entropy anomaly + size anomaly trigger multi-signal fusion |
| **DoS Flood** | IAT + flow-rate anomalies fuse into a single high-severity incident |
| **Baseline Poisoning** | Drift-rejection filter blocks gradual baseline manipulation |
| **C2 Beaconing** | IAT regularity anomaly detects periodic callback patterns |

---

## 📁 Project Structure

```
aegisdiode/
├── backend/
│   ├── aegisdiode/
│   │   ├── __init__.py
│   │   ├── capture/              # Packet capture & ingestion
│   │   │   ├── __init__.py
│   │   │   ├── packet_reader.py  # PCAP reader / live capture
│   │   │   └── ring_buffer.py    # Circular buffer (AF_PACKET sim)
│   │   ├── flows/                # Flow keying & management
│   │   │   ├── __init__.py
│   │   │   ├── flow_tracker.py   # 5-tuple flow tracking
│   │   │   └── flow_table.py     # Active/idle timer management
│   │   ├── features/             # Statistical feature extraction
│   │   │   ├── __init__.py
│   │   │   ├── iat.py            # Inter-Arrival Time analysis
│   │   │   ├── size_stats.py     # Packet size statistics
│   │   │   └── entropy.py        # Shannon entropy computation
│   │   ├── baselines/            # Anti-poison baseline engine
│   │   │   ├── __init__.py
│   │   │   ├── rolling_stats.py  # Rolling statistical baselines
│   │   │   └── drift_reject.py   # Drift-rejection median filter
│   │   ├── detectors/            # Anomaly detection modules
│   │   │   ├── __init__.py
│   │   │   ├── iat_detector.py   # IAT anomaly detector
│   │   │   ├── size_detector.py  # Size anomaly detector
│   │   │   ├── entropy_detector.py # Entropy anomaly detector
│   │   │   └── rate_detector.py  # Flow-rate anomaly detector
│   │   ├── correlation/          # Multi-signal fusion engine
│   │   │   ├── __init__.py
│   │   │   ├── fusion.py         # Time-windowed signal fusion
│   │   │   └── scoring.py        # Deterministic threat scoring
│   │   ├── incidents/            # Incident timeline management
│   │   │   ├── __init__.py
│   │   │   ├── timeline.py       # Incident timeline builder
│   │   │   └── exporter.py       # JSON report exporter
│   │   ├── db/                   # Database layer
│   │   │   ├── __init__.py
│   │   │   ├── init.py           # Schema initialization
│   │   │   ├── models.py         # SQLite models
│   │   │   └── repository.py     # Data access layer
│   │   ├── api/                  # FastAPI server
│   │   │   ├── __init__.py
│   │   │   ├── main.py           # App entry point
│   │   │   ├── routes/           # REST endpoints
│   │   │   │   ├── flows.py
│   │   │   │   ├── alerts.py
│   │   │   │   ├── incidents.py
│   │   │   │   └── dashboard.py
│   │   │   └── websocket.py      # Real-time WebSocket handler
│   │   └── simulator/            # Demo traffic generator
│   │       ├── __init__.py
│   │       ├── traffic_gen.py    # Synthetic traffic generator
│   │       └── attack_patterns.py # Attack pattern templates
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── components/
│   │   │   ├── Dashboard.jsx       # Main SOC dashboard
│   │   │   ├── FlowTable.jsx       # Active flows table
│   │   │   ├── ThreatTimeline.jsx  # Incident timeline view
│   │   │   ├── AnomalyChart.jsx    # Real-time anomaly charts
│   │   │   ├── BaselineMonitor.jsx # Baseline health monitor
│   │   │   └── IncidentDetail.jsx  # Incident drill-down
│   │   ├── hooks/
│   │   │   └── useWebSocket.js     # WebSocket connection hook
│   │   └── styles/
│   ├── package.json
│   ├── vite.config.js
│   └── Dockerfile
├── docker-compose.yml
├── docs/
│   ├── assets/
│   └── ARCHITECTURE.md
├── sample_data/                    # Sample PCAP files for demo
├── README.md
└── IMPLEMENTATION_PLAN.md
```

---

## 📊 SOC Dashboard

The real-time dashboard provides SOC analysts with:

- **Live Flow Monitor** — Active observation flows with feature vectors
- **Threat Timeline** — Correlated incidents on a visual timeline
- **Anomaly Heatmap** — Multi-detector signal visualization
- **Baseline Health** — Rolling baseline status & drift indicators
- **Incident Reports** — Exportable JSON reports for offline analysis

---

## 🔐 Security Guarantees

| Guarantee | How |
|---|---|
| **Zero Attack Surface** | Receive-only mode (`TX=0`) — no packets ever transmitted |
| **Physical Isolation** | Operates behind data diode — cannot breach air gap |
| **Deterministic Scoring** | No ML black boxes — fully auditable threat scores |
| **Anti-Poisoning** | Drift-rejection filters prevent gradual baseline manipulation |
| **Offline Capable** | JSON exports work in fully air-gapped environments |

---

## 🎯 Target Users

- **SOC Analysts & Responders** — Fused incident timelines reduce investigation time
- **Critical Infrastructure** (Power, Defense, NTRO) — Real-time visibility without breaking isolation
- **Air-Gapped Network Engineers** — Reverse-path telemetry while maintaining zero-trust

---

## 📜 License

This project is developed as part of **Smart India Hackathon 2025** by **Team Hexagonal Hive**.

---

<p align="center">
  <sub>Built with ❤️ for securing India's critical infrastructure</sub>
</p>
