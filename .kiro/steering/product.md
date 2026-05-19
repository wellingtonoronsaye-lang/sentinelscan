# SentinelScan – Product Overview

SentinelScan is a modular Flask REST API designed for SOC analysts. It accepts indicators of compromise (IoCs) and fans them out to multiple cyber threat intelligence (CTI) providers in parallel. Results from each provider are normalized to a common verdict schema, aggregated into a single overall verdict, and persisted to SQLite for later investigation.

## Supported IoC Types
- `ip` – IPv4 addresses
- `domain` – domain names
- `url` – full URLs
- `hash` – file hashes (MD5/SHA1/SHA256)

## Verdict Scale
`unknown` → `clean` → `suspicious` → `malicious`  
Aggregation always promotes to the highest severity seen across providers.

## Available CTI Providers
| Key | Class | Notes |
|-----|-------|-------|
| `mock` | `MockProvider` | Deterministic dev provider; no API key needed |
| `otx` / `otxv2` | `OTXConnector` | AlienVault OTX v2; requires `OTX_API_KEY` |
| `virustotal` / `vt` | `VirustotalConnector` | VirusTotal v3; requires `VT_API_KEY` |
|`urlscan.io`|`URLScanConnector`|Requires `URL_SCAN_API_KEY`|

Providers are enabled via the `ENABLED_CTI_PROVIDERS` env var (comma-separated). Default is `mock`.

## API Endpoints
- `POST /api/scan/ioc/scan` – generic IoC scan (preferred)
- `POST /api/scan/ip/scan` – backwards-compatible IP-only scan
- `GET  /api/scan/docs` – Swagger UI
