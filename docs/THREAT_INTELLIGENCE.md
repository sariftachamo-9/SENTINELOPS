# Phase 7 — Threat Intelligence & IOC Enrichment Layer

## Overview
The Threat Intelligence layer transforms the SOC Lab into an enriched investigation platform. It automatically extracts, normalizes, and enriches Indicators of Compromise (IOCs) across alerts, incidents, cases, and investigation workspaces.

---

## Key Capabilities

1. **First-Class IOC Management**: Dedicated storage (`iocs` table) supporting IPv4, IPv6, Domain, URL, File Hash, and Email indicators with strict normalization.
2. **Modular Provider Architecture**: Pluggable provider system (`BaseProvider`) supporting Local Feed, AbuseIPDB v2, and VirusTotal v3.
3. **Database-Backed Caching & Rate Limiting**: Caches intelligence lookups with TTL expiration and enforces per-provider request throttling.
4. **Analyst Override Classification**: Analysts can classify indicators as `MALICIOUS`, `SUSPICIOUS`, `BENIGN`, or `UNKNOWN` with mandatory audit trails.
5. **Transparent Risk Model Integration**: IOC reputation score increases risk transparently with full point explainability.
6. **Graceful Fail-Safe Degradation**: External provider outages or missing credentials return `NOT_CONFIGURED` or `ERROR` without stopping telemetry ingestion.
7. **SSRF & Key Protection**: Excludes private/loopback IP ranges from external API queries and protects API keys from exposure in logs, DB, and REST responses.

---

## System Architecture

```text
Alert / Telemetry Event / Analyst Query
              │
              ▼
      IOC Normalizer (IPv4, IPv6, Domain, URL, Hash, Email)
              │
              ▼
      Enrichment Manager ──► Database Cache (ioc_enrichment_cache)
              │
      ┌───────┴─────────────────────────┐
      ▼                                 ▼
Local Threat Feed             External Adapters (AbuseIPDB / VT)
(Always Configured)           (Return NOT_CONFIGURED if no key)
      │                                 │
      └───────┬─────────────────────────┘
              ▼
   Normalized Intel Result (MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN)
              │
              ▼
 Alert & Risk Engine Integration + Investigation Workspace
```
