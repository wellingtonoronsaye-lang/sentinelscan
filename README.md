# SentinelScan

SentinelScan is a modular Flask API for SOC analysts to scan indicators of compromise through multiple CTI providers in parallel. Provider results are normalized, aggregated into an overall verdict, and stored in SQLite for later investigation.

## Features

- Parallel CTI scans through a provider plugin registry
- Flask Blueprint API mounted at `/api/scan`
- Generic IoC scanning for `ip`, `domain`, `url`, and `hash`
- Backwards-compatible IP scan endpoint
- SQLite persistence for scan summaries and provider results
- Development mock provider enabled by default
- Swagger UI through `flask-restx`

## Project Structure

```text
app/
  cti/
    verdicts.py              # Verdict normalization and aggregation
  connectors/
    base.py                  # CTI provider contract
    registry.py              # Enabled provider registry
    otxv2.py                 # AlienVault OTX provider
  db/
    sqlite.py                # SQLite schema and persistence helpers
  plugins/
    mock_provider/
      plugin.py              # Local development CTI provider
  scan/
    blueprint.py             # Flask Blueprint and RESTX API
    models.py                # Swagger request/response models
    orchestrator.py          # Parallel provider execution
    routes.py                # Scan endpoints
```

## Configuration

Copy `.env-example` to `.env` and update values as needed.

```env
FLASK_SECRET_KEY=change-me-please
ENABLED_CTI_PROVIDERS=mock
SENTINEL_DB_PATH=instance/sentinel_scan.sqlite3

OTX_API_KEY=your_otx_api_key_here
OTX_RATE_LIMIT=10
```

`ENABLED_CTI_PROVIDERS` is a comma-separated list. Currently available values are:

- `mock`
- `otx`

## Running

```bash
uv sync
uv run python run.py
```

If `uv` is not on PATH but the local virtual environment exists:

```powershell
.\.venv\Scripts\python.exe run.py
```

Swagger UI is available at:

```text
http://localhost:5000/api/scan/docs
```

## API

### Generic IoC Scan

`POST /api/scan/ioc/scan`

```json
{
  "ioc": "evil.example",
  "ioc_type": "domain"
}
```

### IP Scan

`POST /api/scan/ip/scan`

```json
{
  "ip": "8.8.8.8"
}
```

### Response

```json
{
  "scan_id": 1,
  "ioc": "evil.example",
  "ioc_type": "domain",
  "overall_verdict": "malicious",
  "sources_scanned": 1,
  "results": [
    {
      "source": "MockCTI",
      "ioc": "evil.example",
      "ioc_type": "domain",
      "verdict": "malicious",
      "confidence": 0.9,
      "details": {},
      "error": null
    }
  ]
}
```

## Adding A Provider

Create a provider class that extends `BaseConnector`, set the supported IoC flags, implement the scan methods you support, then register it in `app/connectors/registry.py`.

```python
from app.connectors.base import BaseConnector


class ExampleProvider(BaseConnector):
    name = "ExampleProvider"
    supports_ip = True

    def scan_ip(self, ip: str) -> dict:
        return {
            "source": self.name,
            "ioc": ip,
            "ioc_type": "ip",
            "verdict": "clean",
            "confidence": 0.1,
            "details": {},
            "error": None,
        }
```

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests -p no:cacheprovider
.\.venv\Scripts\python.exe -m ruff check app tests
```
