# IOC Model Specifications & Normalization Rules

## Supported IOC Types

1. `ipv4`: Validated via `ipaddress.IPv4Address`. Example: `198.51.100.99`.
2. `ipv6`: Validated via `ipaddress.IPv6Address`. Example: `2001:db8::1`.
3. `domain`: Lowercase domain string without protocol/port/path. Example: `evil-phish.net`.
4. `url`: Scheme + lowercase host + path. Example: `http://malicious-site.org/payload.exe`.
5. `file_hash`: MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) string in lowercase.
6. `email`: Lowercase `user@domain` string.

---

## IOC Schema

| Field | Type | Description |
|---|---|---|
| `id` | TEXT PRIMARY KEY | Formatted as `IOC-YYYYMMDD-XXXXXX` |
| `type` | TEXT | `ipv4`, `ipv6`, `domain`, `url`, `file_hash`, `email` |
| `value` | TEXT | Raw input value |
| `normalized_value` | TEXT | Cleaned, normalized lookup string (UNIQUE with type) |
| `confidence` | INTEGER | Confidence score (0–100) |
| `severity` | TEXT | `critical`, `high`, `medium`, `low`, `info` |
| `reputation` | TEXT | `MALICIOUS`, `SUSPICIOUS`, `BENIGN`, `UNKNOWN` |
| `analyst_classification` | TEXT | Analyst override classification |
| `analyst_override_reason` | TEXT | Mandatory audit reason for manual override |
| `classified_by` | TEXT | Analyst username |
| `classified_at` | TEXT | ISO timestamp |

---

## Normalization & SSRF Safety Rules

- **Private & Loopback IPs**: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` are flagged as private and excluded from external provider API lookups.
- **URL Sanitization**: URLs are parsed for host/path without initiating HTTP requests to target destinations.
- **Input Truncation**: Inputs exceeding 2048 characters are safely truncated to prevent buffer overflow/ReDoS attacks.
