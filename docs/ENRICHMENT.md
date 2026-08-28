# Enrichment Architecture & Risk Integration

## Enrichment Flow

1. **Extraction**: Alerts and telemetry events undergo automated IOC extraction (`IOCNormalizer.extract_iocs_from_dict`).
2. **Provider Lookups**: IOCs are evaluated across configured providers (Local Feed, AbuseIPDB, VirusTotal) with cache checks.
3. **Reputation Aggregation**:
   - `MALICIOUS`: High confidence threat indicator found.
   - `SUSPICIOUS`: Moderate threat activity detected.
   - `BENIGN`: Clean indicator or empty file hash.
   - `UNKNOWN`: Unmatched or non-authoritative data.
   - `NOT_CONFIGURED`: Provider disabled due to missing API keys.
4. **Alert Attachment**: Threat intel is attached under `alert["threat_intel"]` without overwriting raw evidence.

---

## Transparent Risk Scoring Formula

Threat intelligence matches adjust alert risk scores transparently:

- **Confirmed Malicious Match**: `+15 points` to `ioc_reputation` factor.
- **Suspicious Match**: `+10 points` to `ioc_reputation` factor.
- **Clean / Unknown Match**: `+0 points`.

Final Risk Formula:
$$\text{Risk} = \text{BaseSeverity} + \text{EventFrequency} + \text{Confidence} + \text{AssetCriticality} + \text{AccountSensitivity} + \text{CorrelationStrength} + \text{IOCReputation}$$
