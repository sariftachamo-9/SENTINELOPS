# Threat Intelligence Provider Adapters

## Supported Providers

### 1. Local Threat Intel Feed (`LocalFeedProvider`)
- **Status**: Always Enabled.
- **Data Source**: SQLite `iocs` table and built-in static local feeds.
- **Coverage**: IP, Domain, File Hash, Email.

---

### 2. AbuseIPDB Provider (`AbuseIPDBProvider`)
- **Environment Variable**: `ABUSEIPDB_API_KEY`
- **Coverage**: IPv4 and IPv6.
- **Behavior**:
  - If `ABUSEIPDB_API_KEY` is set: queries `https://api.abuseipdb.com/api/v2/check`.
  - If missing/empty: returns `lookup_status="NOT_CONFIGURED"`.

---

### 3. VirusTotal Provider (`VirusTotalProvider`)
- **Environment Variable**: `VIRUSTOTAL_API_KEY`
- **Coverage**: File Hash, Domain, IPv4, IPv6.
- **Behavior**:
  - If `VIRUSTOTAL_API_KEY` is set: queries `https://www.virustotal.com/api/v3/`.
  - If missing/empty: returns `lookup_status="NOT_CONFIGURED"`.

---

## Secret Secrecy Guarantees

- **No Key Leaks**: API credentials are read from `os.getenv()` at runtime.
- **Audit & Response Protection**: API keys are excluded from `raw_details` dictionary, REST API responses, audit logs, and database records.
- **Non-Blocking Fault Isolation**: External timeouts (3s limit) and network failures return `lookup_status="ERROR"` and never stop telemetry ingestion or SOC operations.
