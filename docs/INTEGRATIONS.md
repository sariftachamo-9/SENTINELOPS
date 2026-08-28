# SOC Platform — Integrations & External Agent Setup Guide

## Integration Status Matrix

| Integration | Type | Current Status | Connection Path | Phase Planned |
|-------------|------|----------------|-----------------|---------------|
| **Windows Event / Sysmon** | Log Agent | **NOT CONFIGURED** | Ingestion API (`POST /api/v1/telemetry/ingest`) via Winlogbeat / NXLog | Ready for Agent (Phase 4) |
| **Linux Auth / Syslog** | Log Agent | **NOT CONFIGURED** | Ingestion API via Filebeat / rsyslog | Ready for Agent (Phase 4) |
| **Suricata IDS** | Network Sensor | **NOT CONFIGURED** | EVE JSON forwarded to `/api/v1/telemetry/ingest` | Prepared interface (Phase 4) |
| **Zeek NSM** | Network Sensor | **NOT CONFIGURED** | JSON logs forwarded to `/api/v1/telemetry/ingest` | Prepared interface (Phase 4) |
| **Wazuh Manager** | SIEM / EDR | **NOT CONFIGURED** | Custom adapter wrapper via `SIEMAdapter` interface | Prepared interface (Phase 4) |
| **Elasticsearch / OpenSearch**| Event Store | **NOT CONFIGURED** | Abstract `StorageBackend` implementation | Prepared interface (Phase 4) |

> ⚠️ **Important Policy:** The platform NEVER displays an integration as `ONLINE` or `CONNECTED` unless a real agent or sensor is actively transmitting verified telemetry.

---

## Endpoint Configuration Guides

### 1. Windows Endpoint Setup (Winlogbeat)

#### Step 1: Install Winlogbeat on Windows Host
Download and extract Winlogbeat from Elastic.

#### Step 2: Configure `winlogbeat.yml`
```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4688, 4720, 4726
  - name: Microsoft-Windows-Sysmon/Operational

output.http:
  hosts: ["http://soc-platform.corp.internal:8001/api/v1/telemetry/ingest/batch"]
  headers:
    Authorization: "Bearer <YOUR_AGENT_JWT_TOKEN>"
    Content-Type: "application/json"
  ssl.verification_mode: "none"
```

#### Step 3: Start Service
```powershell
Start-Service winlogbeat
```

---

### 2. Linux Endpoint Setup (Filebeat)

#### Step 1: Configure `filebeat.yml`
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/auth.log
      - /var/log/secure
      - /var/log/syslog

output.http:
  hosts: ["http://soc-platform.corp.internal:8001/api/v1/telemetry/ingest/batch"]
  headers:
    Authorization: "Bearer <YOUR_AGENT_JWT_TOKEN>"
```

---

### 3. Syslog Forwarding (rsyslog / syslog-ng)

Add to `/etc/rsyslog.d/50-soc.conf`:
```text
*.* @soc-platform.corp.internal:514
```
Or use a lightweight Python bridge to translate UDP 514 syslog traffic to `POST /api/v1/telemetry/ingest`.
