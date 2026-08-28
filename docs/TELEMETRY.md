# SOC Platform — Telemetry Architecture Guide

## Overview
Phase 3 introduces a production-grade, modular telemetry ingestion, validation, normalization, storage, and detection pipeline.

---

## Data Pipeline Architecture

```text
Windows / Linux / Network / Application / Syslog
                       │
                       ▼
             [ Ingestion API Endpoint ]
        POST /api/v1/telemetry/ingest (Single)
        POST /api/v1/telemetry/ingest/batch (Batch)
                       │
                       ▼
             [ TelemetryValidator ]
   (Rejects malformed JSON, bad IPs, injection attempts)
                       │
                       ▼
       [ EnhancedTelemetryNormalizer ]
   (Dispatches to Windows/Linux/Network/Syslog/App adapter)
                       │
                       ▼
             [ EventDeduplicator ]
   (SHA256 content hashing, sliding window, occurrence counter)
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
     [ StorageBackend ]   [ AlertRulesEngine ]
  (telemetry_events DB)   (Evaluates rules against normalized event)
                                 │
                                 ▼
                          [ Alert Engine ]
```

---

## Component Details

### 1. Ingestion Layer
- Authenticated JWT bearer token required.
- Rate-limited per client IP.
- Single and batch endpoints (up to 500 events per batch).
- Returns structured JSON responses with event IDs, deduplication flags, and alert counts.

### 2. Validation Layer (`src/telemetry/validator.py`)
- Verifies IPv4/IPv6 syntax.
- Enforces port range (0-65535).
- Enforces 512KB payload ceiling to prevent memory exhaustion attacks.
- Rejects SQL injection / command injection characters in string fields (`username`, `hostname`).

### 3. Normalization & Adapter Layer (`src/telemetry/adapters/`)
Source adapters normalize vendor logs into a flat canonical schema:
- `WindowsAdapter`: Windows Event IDs (4624, 4625, 4688, 4720, etc.), Sysmon (1, 3, 7, 8, 10, 11, 13), PowerShell (4103, 4104).
- `LinuxAdapter`: SSHD logins, sudo command executions, PAM authentication, auditd events.
- `NetworkAdapter`: Firewall allow/deny, DNS queries, HTTP transactions, flow data, generic IDS alerts.
- `ApplicationAdapter`: Web app logs, API errors, database queries, WAF alerts.
- `SyslogAdapter`: RFC 3164 and RFC 5424 syslog messages.
- `GenericAdapter`: Fallback JSON event passthrough.

### 4. Deduplication Layer (`src/telemetry/deduplication.py`)
- Calculates SHA256 over key tuple: `(source_ip, destination_ip, event_type, username, process_name, hostname, source_type)`.
- 60-second sliding window.
- Duplicate events update `occurrence_count` and `last_seen` timestamp without silently discarding raw events.

### 5. Storage Layer (`src/telemetry/storage.py`)
- Security Telemetry stored in `telemetry_events` table (separated from application operational data).
- Abstract `StorageBackend` interface allows drop-in replacement with PostgreSQL, OpenSearch, or Elasticsearch in Phase 4.

### 6. Event Search & Timeline (`src/telemetry/search.py`)
- Parameterized search API with filtering by time range, IP, host, user, severity, event type, process name, and asset ID.
- Chronological entity timeline for host, user, IP, asset, or incident.

### 7. Telemetry Health (`src/telemetry/health.py`)
- Monitors EPS (rolling 60s), total events processed, rejected count, error count, and adapter statuses.
