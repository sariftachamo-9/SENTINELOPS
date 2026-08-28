# SOC Platform — Normalized Event Schema (Phase 3)

## Canonical Normalized Event Model

Every security event ingested into the platform is normalized into the `NormalizedEvent` schema before storage or detection processing.

---

## Field Reference Table

| Field Name | Data Type | Required | Description | Example |
|------------|-----------|----------|-------------|---------|
| `event_id` | String | Yes (Auto) | Unique event identifier (`EVT-XXXXXXXX`) | `EVT-A1B2C3D4E5F67890` |
| `timestamp` | String (ISO 8601) | Yes | Event occurrence timestamp | `2026-08-23T14:30:00Z` |
| `ingestion_timestamp` | String (ISO 8601) | Yes (Auto) | Platform receipt timestamp | `2026-08-23T14:30:01Z` |
| `source_type` | String | Yes | Primary taxonomy: `windows`, `linux`, `network`, `application`, `syslog`, `generic` | `windows` |
| `source_product` | String | No | Specific logging product | `WinEvtLog` |
| `source_sensor` | String | No | Collecting agent or sensor ID | `agent-win-01` |
| `environment` | String | Yes | `lab`, `simulation`, `production`, `staging` | `lab` |
| `hostname` | String | No | Reporting computer hostname / FQDN | `DC-01.corp.internal` |
| `asset_id` | String | No | Asset inventory ID | `AST-1042` |
| `fqdn` | String | No | Fully qualified domain name | `dc-01.corp.internal` |
| `source_ip` | String | No | Source IPv4 or IPv6 address | `192.168.1.50` |
| `destination_ip` | String | No | Destination IPv4 or IPv6 address | `10.0.0.1` |
| `source_port` | Integer | No | Source port (0–65535) | `49152` |
| `destination_port` | Integer | No | Destination port (0–65535) | `445` |
| `protocol` | String | No | Network protocol (`tcp`, `udp`, `icmp`, `dns`, `http`) | `tcp` |
| `network_direction` | String | No | `inbound`, `outbound`, `internal`, `unknown` | `inbound` |
| `bytes_sent` | Integer | No | Bytes sent in network transaction | `1024` |
| `bytes_received` | Integer | No | Bytes received in network transaction | `4096` |
| `username` | String | No | User / account name | `jdoe` |
| `domain` | String | No | Windows domain or auth realm | `CORP` |
| `user_id` | String | No | Unique user SID / UID | `S-1-5-21-...` |
| `process_name` | String | No | Process executable name or path | `powershell.exe` |
| `process_id` | Integer | No | Process ID (PID) | `4820` |
| `parent_process` | String | No | Parent process name | `cmd.exe` |
| `parent_process_id` | Integer | No | Parent process ID (PPID) | `1024` |
| `command_line` | String | No | Full command line string | `powershell.exe -Enc ...` |
| `executable_hash` | String | No | SHA256 executable hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `event_type` | String | No | Normalized event classification | `Failed Logon` |
| `event_code` | String | No | Source event code (e.g. EventID) | `4625` |
| `severity` | String | Yes | `low`, `medium`, `high`, `critical`, `info`, `unknown` | `high` |
| `action` | String | No | Executed action: `login`, `execute`, `connect`, `read`, `write`, `delete` | `login` |
| `outcome` | String | No | Action result: `success`, `failure`, `blocked`, `allowed` | `failure` |
| `message` | String | No | Human-readable event summary message | `EventID=4625 \| User=jdoe \| Host=DC-01` |
| `risk_score` | Integer | No | Calculated risk score (0–100) | `75` |
| `correlation_id` | String | No | Correlation identifier linking multi-stage events | `CORR-99281` |
| `session_id` | String | No | User session identifier | `SESS-1029` |
| `tags` | List[String] | No | Taxonomical and operational tags | `["windows", "authentication"]` |
| `raw_event` | Dict | Yes | Original raw log event preserved verbatim | `{...}` |
| `content_hash` | String | No | Deduplication SHA256 hash | `f2ca1bb6c...` |
| `occurrence_count` | Integer | No | Duplicate occurrence counter | `1` |
| `first_seen` | String (ISO 8601) | No | First observed timestamp | `2026-08-23T14:30:00Z` |
| `last_seen` | String (ISO 8601) | No | Most recent observed timestamp | `2026-08-23T14:30:00Z` |
| `processed` | Boolean | No | Indicates processing through detection engine | `true` |
| `simulation` | Boolean | Yes | Indicates lab simulation data | `true` |

---

## Controlled Vocabularies

### Severities
- `info`: Informational activity (successful login, service start)
- `low`: Minor event, low security impact
- `medium`: Notable event requiring analyst awareness
- `high`: Suspicious behavior, likely security incident
- `critical`: Confirmed threat, active attack or exploitation

### Source Types
- `windows`: Windows Event Logs, Sysmon, PowerShell
- `linux`: Syslog, SSH, Sudo, PAM, Auditd
- `network`: Firewall, DNS, HTTP, Network Flow, IDS
- `application`: Web application, API, Database, WAF
- `syslog`: Standard RFC 3164/5424 syslog
- `generic`: Generic JSON passthrough
