<p align="center">
  <img src="docs/assets/aegisdiode-logo.svg" alt="AegisDiode Logo" width="120" />
</p>

<h1 align="center">AegisDiode</h1>

<p align="center">
  <strong>Passive Threat Correlation for Unidirectional Networks</strong><br/>
  <em>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#tech-stack">Tech Stack</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#demo">Demo</a> &bull;
  <a href="#deployment">Deployment</a>
</p>

---

## Problem Statement

> **Smart India Hackathon 2026 — Problem Statement ID: SIH26145**
> *Theme: Blockchain & Cybersecurity | Category: Software*
> **Team: Hexagonal Hive (ID: 172598)**

Traditional network security tools (IDS/IPS, firewalls) rely on **bidirectional TCP handshakes** and **conversation state** to detect threats. In **unidirectional networks** (data diodes) used by critical infrastructure (power grids, defense, NTRO), there is **no return path** — making conventional tools useless.

**AegisDiode** solves this by shifting from conversation-state analysis to **Observable Behavioral Evidence**, enabling passive threat detection without breaking physical diode isolation.

---

## Features

### Core Innovations

| Feature | Description |
|---|---|
| **Zero-Trust Hardware Safety** | Software-enforced receive-only engine (`TX=0`) guarantees physical unidirectional security |
| **Observation Flow Keying** | Groups unidirectional traffic using **5-Tuple + Time Windows** (60s active / 15s idle) |
| **Statistical Feature Extraction** | Measures **Inter-Arrival Time (IAT)**, packet sizes, and **Shannon Entropy** directly from metadata |
| **JA4+ Protocol Fingerprinting** | Passive TLS/QUIC session categorization from metadata without payload decryption |
| **Welch FFT Beaconing Detection** | Power Spectral Density analysis of IAT series to detect C2 callback periodicity |
| **Anti-Poison Baselines** | Rolling statistical filters with **drift-rejection median** updates prevent baseline manipulation |
| **Multi-Signal Fusion** | Fuses isolated anomalies into **correlated incident timelines** — eliminates alert fatigue |
| **6-Vector Auditable Scoring** | Deterministic scoring across IAT, size, entropy, flow-rate, JA4+, and beacon dimensions |
| **STIX 2.1 / JSON-LD Export** | Standardized incident schema with MITRE ATT&CK tactic mapping for air-gapped SOC analysis |
| **Zero Gap Initialization** | Initializes tracking on the **first seen packet**, bypassing missing SYN/ACK handshakes |

### Paradigm Shift

```
Traditional IDS:  Conversation State  →  Requires bidirectional traffic  →  Fails on data diodes
AegisDiode:       Observable Behavior  →  Works with receive-only traffic →  Designed for data diodes
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│              AEGISDIODE — PASSIVE UNIDIRECTIONAL THREAT PIPELINE        │
│                                                                         │
│  ┌──────────────────────────┐                                           │
│  │ Raw Unidirectional        │  Input from hardware-enforced             │
│  │ Traffic Mirror            │  Data Diode tap (TX=0)                    │
│  └────────────┬─────────────┘                                           │
│               ▼                                                         │
│  ┌──────────────────────────┐                                           │
│  │ AF_PACKET Ring Buffer     │  Zero-copy ingestion in                   │
│  │ (TX=0)                    │  receive-only mode                        │
│  └────────────┬─────────────┘                                           │
│               ▼                                                         │
│  ┌──────────────────────────┐                                           │
│  │ Stateless Flow Keyer      │  5-Tuple + Time Windows                   │
│  │                           │  micro (100ms) to macro (60s)             │
│  └────────────┬─────────────┘                                           │
│               ▼                                                         │
│  ┌──────────────────────────┐                                           │
│  │ Deep Packet Anomalies &   │  IAT, Sizes, Shannon Entropy,             │
│  │ Protocol Fingerprinting   │  JA4+ Fingerprinting                      │
│  └────────────┬─────────────┘                                           │
│               ▼                                                         │
│  ┌──────────────────────────┐                                           │
│  │ Correlation & Scoring     │  6-vector deterministic scoring            │
│  │ Engine                    │  + multi-signal fusion                     │
│  └────────────┬─────────────┘                                           │
│               ▼                                                         │
│  ┌──────────────────────────┐                                           │
│  │ Actionable Incident       │  STIX 2.1 / JSON-LD Schema                │
│  │ Timeline                  │  MITRE ATT&CK tactic mapping              │
│  └──────────────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Pipeline Stages

1. **Packet Capture** — Ingests raw unidirectional packets via `AF_PACKET` ring buffers in receive-only mode (TX=0). Demo uses PCAP replay via Scapy.
2. **Flow Keying** — Groups packets into observation flows using `(src_ip, dst_ip, src_port, dst_port, protocol)` + active/idle timers (60s/15s). Zero-gap initialization on first packet.
3. **Feature Extraction** — Computes per-flow statistics: IAT distribution, packet size histogram, Shannon entropy, JA4+ TLS fingerprints.
4. **Baseline Engine** — Maintains rolling statistical baselines with drift-rejection median filter to prevent slow poisoning attacks.
5. **Anomaly Detection** — Multi-detector system: IAT, size, entropy, flow-rate, JA4+ suspicion, Welch FFT beaconing.
6. **Correlation Engine** — Time-windowed multi-signal fusion with deterministic 6-vector threat scoring and MITRE ATT&CK tactic classification.
7. **Incident Timeline** — Produces actionable, auditable STIX 2.1 / JSON-LD incident reports for SOC analysts.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Ingestion Engine** | Python 3.11 + Scapy (prod: Go 1.22 + AF_PACKET) | Packet capture in receive-only mode |
| **Analytics & Baselines** | NumPy, SciPy, Statistics | Statistical features, Shannon entropy, Welch FFT PSD |
| **Protocol Analysis** | Custom JA4+ implementation | Passive TLS/QUIC fingerprinting |
| **Data Persistence** | SQLite | Lightweight embedded database (air-gap compatible) |
| **Threat Intelligence** | STIX 2.1 / JSON-LD, MITRE ATT&CK | Standardized incident export & tactic mapping |
| **API Server** | FastAPI + WebSockets | Real-time SOC interface with REST + streaming |
| **Dashboard** | React 18 + TypeScript + Recharts | Real-time threat visualization & incident management |
| **Deployment** | Docker + Docker Compose | Single-command deployment on commodity hardware |

> **Production Architecture:** The target specifies Go 1.22 + AF_PACKET with eBPF/XDP for the ingestion engine, targeting 10 Gbps / 100K flows/sec / <5ms latency / <512 MB RAM. This demo prototype uses Python with identical pipeline semantics.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ & npm
- Docker & Docker Compose (optional)

### Option 1: Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m aegisdiode.db.init
uvicorn aegisdiode.api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Option 2: Docker Compose

```bash
docker-compose up --build
```

- Dashboard: **http://localhost:5173**
- API docs: **http://localhost:8000/docs**

---

## Demo

The demo includes a **traffic simulator** that generates realistic unidirectional network traffic with injected attack patterns:

```bash
# Mixed traffic with random attack injection
python -m aegisdiode.simulator.traffic_gen --mode mixed --duration 300

# Specific attack scenarios
python -m aegisdiode.simulator.traffic_gen --attack port_scan
python -m aegisdiode.simulator.traffic_gen --attack data_exfil
python -m aegisdiode.simulator.traffic_gen --attack dos_flood
python -m aegisdiode.simulator.traffic_gen --attack slow_poison
python -m aegisdiode.simulator.traffic_gen --attack beaconing
```

### Attack Detection Scenarios

| Scenario | Detectors Triggered | MITRE ATT&CK |
|---|---|---|
| **Port Scan** | Flow-rate + IAT anomaly fused into incident | Reconnaissance (TA0043) / T1046 |
| **Data Exfiltration** | Entropy + size anomaly multi-signal fusion | Exfiltration (TA0010) / T1041 |
| **DoS Flood** | IAT + flow-rate fused high-severity incident | Impact (TA0040) / T1498 |
| **Baseline Poisoning** | Drift-rejection filter blocks manipulation | Defense Evasion (TA0005) / T1070 |
| **C2 Beaconing** | Welch FFT PSD detects periodic callbacks | Command & Control (TA0011) / T1071 |

---

## Project Structure

```
aegisdiode/
├── backend/
│   ├── aegisdiode/
│   │   ├── config.py              # Global configuration
│   │   ├── capture/               # Packet capture & ingestion
│   │   │   ├── packet_reader.py   # PCAP reader / live capture
│   │   │   └── ring_buffer.py     # Circular buffer (AF_PACKET sim)
│   │   ├── flows/                 # Flow keying & management
│   │   │   ├── flow_tracker.py    # 5-tuple + zero-gap initialization
│   │   │   └── flow_table.py      # Active/idle timer management
│   │   ├── features/              # Statistical feature extraction
│   │   │   ├── iat.py             # Inter-Arrival Time analysis
│   │   │   ├── size_stats.py      # Packet size statistics
│   │   │   ├── entropy.py         # Shannon entropy computation
│   │   │   └── ja4_fingerprint.py # JA4+ passive TLS fingerprinting
│   │   ├── baselines/             # Anti-poison baseline engine
│   │   │   ├── rolling_stats.py   # Rolling statistical baselines
│   │   │   └── drift_reject.py    # Drift-rejection median filter
│   │   ├── detectors/             # Anomaly detection modules
│   │   │   ├── iat_detector.py    # IAT anomaly detector
│   │   │   ├── size_detector.py   # Size anomaly detector
│   │   │   ├── entropy_detector.py # Entropy anomaly detector
│   │   │   ├── rate_detector.py   # Flow-rate anomaly detector
│   │   │   └── beacon_detector.py # Welch FFT C2 beaconing detector
│   │   ├── correlation/           # Multi-signal fusion engine
│   │   │   ├── fusion.py          # Time-windowed signal fusion
│   │   │   ├── scoring.py         # 6-vector threat scoring
│   │   │   └── mitre_mapping.py   # MITRE ATT&CK tactic mapping
│   │   ├── incidents/             # Incident timeline management
│   │   │   ├── timeline.py        # Incident timeline builder
│   │   │   ├── exporter.py        # JSON report exporter
│   │   │   └── stix_exporter.py   # STIX 2.1 / JSON-LD export
│   │   ├── db/                    # Database layer
│   │   │   ├── init.py            # Schema initialization
│   │   │   ├── models.py          # SQLite models
│   │   │   └── repository.py      # Data access layer
│   │   ├── api/                   # FastAPI server
│   │   │   ├── main.py            # App entry point
│   │   │   ├── websocket.py       # Real-time WebSocket handler
│   │   │   └── routes/            # REST endpoints
│   │   └── simulator/             # Demo traffic generator
│   │       ├── traffic_gen.py     # Synthetic traffic generator
│   │       └── attack_patterns.py # Attack pattern templates
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/            # SOC dashboard views
│   │   ├── hooks/                 # WebSocket hooks
│   │   └── types/                 # API type definitions
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml
├── docs/
├── sample_data/                   # Sample PCAP files for demo
├── README.md
├── IMPLEMENTATION.md
└── AGENT.md
```

---

## SOC Dashboard

The real-time React dashboard provides SOC analysts with:

- **Live Flow Monitor** — Active observation flows with 6-vector feature scores
- **Threat Timeline** — Correlated incidents on a visual timeline
- **Anomaly Heatmap** — Multi-detector signal visualization
- **Baseline Health** — Rolling baseline status & drift-rejection indicators
- **Beacon Analysis** — Welch FFT Power Spectral Density visualization
- **Incident Reports** — Exportable STIX 2.1 / JSON-LD reports for air-gapped SOC analysis
- **MITRE ATT&CK View** — Tactic/technique classification per incident

---

## Security Guarantees

| Guarantee | Mechanism |
|---|---|
| **Zero Attack Surface** | Receive-only mode (`TX=0`) — no packets ever transmitted |
| **Physical Isolation** | Operates behind data diode — cannot breach air gap |
| **Deterministic Scoring** | 6-vector auditable scoring — no ML black boxes |
| **Anti-Poisoning** | Drift-rejection median filter blocks gradual baseline manipulation |
| **Offline Capable** | STIX 2.1 / JSON-LD exports work in fully air-gapped environments |
| **No External Dependencies** | Air-gapped compatible — all processing is local |

---

## Performance Targets (Production)

| Metric | Target |
|---|---|
| Throughput | 10 Gbps sustained line-rate |
| Flow capacity | 100,000 flows/sec |
| Detection latency | < 5 ms bounded streaming |
| Memory | < 512 MB RAM (statically bounded) |
| Packet loss | 0% |

---

## Target Users

- **SOC Analysts & Responders** — Fused incident timelines eliminate alert fatigue and cut investigation time
- **National Security & Defense Enclaves (NTRO)** — Real-time threat intelligence from mirrored optical taps without breaking unidirectional isolation
- **Air-Gapped Network Engineers** — Reverse-path telemetry while maintaining strict zero-trust enclave isolation

---

## Research & References

### Industry & Kernel Standards
- **NIST SP 800-82 Rev. 3 & MIT Research (CSIIRW)** — Unidirectional data diode architectures for air-gapped critical infrastructure
- **Linux Kernel AF_PACKET Interface (PACKET_MMAP / eBPF XDP)** — Zero-copy ring-buffer architectures for multi-gigabit packet inspection
- **OASIS STIX 2.1 & MITRE ATT&CK Framework** — Standardized schema for threat indicators and tactic mapping (TA0011, TA0043, TA0010)

### Mathematical & Theoretical Foundations
- **JA4+ Network Fingerprinting (Fox-IT / Althouse, 2023)** — TLS/QUIC session categorization from metadata without payload decryption
- **Welch FFT Power Spectral Density (IEEE, 1967)** — Botnet C2 beacon detection using IAT frequency analysis
- **Validation Datasets (CIC-IDS2018 & UNSW-NB15)** — Empirical benchmarks for volumetric DDoS, DGA entropy, and asymmetric exfiltration ratios

---

## License

This project is developed as part of **Smart India Hackathon 2026** by **Team Hexagonal Hive**.

---

<p align="center">
  <sub>Built for securing India's critical infrastructure</sub>
</p>
