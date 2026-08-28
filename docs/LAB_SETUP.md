# SOC Laboratory — Setup & Deployment Guide

## Overview
This document describes how to deploy and run the Enterprise SOC Platform in a local laboratory environment.

---

## Architecture Diagram

```text
  Windows Agent / Linux Agent / Network Sensor / Application
                          │
                          ▼
            REST Ingestion API (Port 8001)
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
      Validation Layer            Rate Limiter
            │                           │
            ▼                           ▼
    Normalization Layer            Auth Middleware
            │
            ▼
    Deduplication Layer
            │
      ┌─────┴─────────────┐
      ▼                   ▼
  Event Store       Detection Engine (Rules + ML)
  (SQLite/OpenSearch)     │
                          ▼
                     Alert Engine
                          │
                          ▼
                     SOC Dashboard (Port 8002)
```

---

## Local Startup Instructions

### 1. Prerequisites
- Python 3.9+
- Virtual environment (`venv`)

### 2. Environment Setup
```bash
cd "/home/jenishkali/Desktop/Soc Lab"
source .env
```

Ensure `.env` contains:
```env
JWT_SECRET=your_secure_random_hex_key
LAB_ADMIN_PASSWORD=YourStrongPass123!
```

### 3. Database Initialization
```bash
./venv/bin/python -c "from src.database import Database; db = Database(); print('DB Initialized')"
```
On first run, `lab_credentials.txt` is generated with unique passwords for all 7 lab accounts.

### 4. Running the Platform
Start API server (Port 8001):
```bash
./venv/bin/python -m uvicorn src.api:app --host 0.0.0.0 --port 8001
```

Start Web UI (Port 8002):
```bash
./venv/bin/python src/web_ui.py
```

### 5. Accessing the Dashboard
- Web UI: `http://localhost:8002`
- OpenAPI Documentation: `http://localhost:8001/docs`

---

## Lab User Accounts & Roles

Retrieve passwords from `lab_credentials.txt`:
```bash
cat lab_credentials.txt
```

| Username | Role | Permissions |
|----------|------|-------------|
| `analyst_l1` | SOC Analyst L1 | Read alerts, assign, update |
| `analyst_l2` | SOC Analyst L2 | Triage, create incidents, ingest telemetry |
| `threat_hunter` | Threat Hunter | Query telemetry, execute hunting queries |
| `responder` | Incident Responder | Close incidents, execute SOAR playbooks |
| `engineer` | Detection Engineer | Manage rules, view MITRE coverage |
| `manager` | SOC Manager | View reports, audit logs, dashboards |
| `readonly` | Read Only | View alerts and telemetry (no write) |
