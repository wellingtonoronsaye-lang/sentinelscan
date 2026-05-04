# Project Structure

```
sentinel-scan/
├── run.py                        # Entry point — creates and runs the Flask app
├── pyproject.toml                # Project metadata and dependencies
├── .env / .env-example           # Runtime configuration (never commit .env)
├── .flaskenv                     # Flask CLI settings (FLASK_APP, FLASK_ENV, port)
├── instance/                     # SQLite databases (gitignored runtime data)
├── tests/                        # Pytest test suite (one file per concern)
└── app/
    ├── factory.py                # create_app() — app factory, blueprint registration
    ├── config.py                 # Config class — reads env vars with defaults
    ├── extensions.py             # Flask extension singletons (limiter)
    ├── connectors/
    │   ├── base.py               # BaseConnector ABC — capability flags + result schema
    │   ├── registry.py           # get_enabled_connectors(), ConnectorRegistry
    │   ├── otxv2.py              # AlienVault OTX v2 connector
    │   └── virustotal.py         # VirusTotal v3 connector
    ├── cti/
    │   └── verdicts.py           # normalize_verdict(), aggregate_verdict()
    ├── db/
    │   └── sqlite.py             # init_db(), save_scan() — raw sqlite3, no ORM
    ├── plugins/
    │   └── mock_provider/
    │       └── plugin.py         # MockProvider — deterministic dev connector
    └── scan/
        ├── blueprint.py          # Flask Blueprint + flask-restx Api instance
        ├── models.py             # Swagger request/response model definitions
        ├── routes.py             # Route handlers (IPScan, IoCScan resources)
        └── orchestrator.py       # ParallelOrchestrator — ThreadPoolExecutor fan-out
```

## Architectural Layers

```
HTTP Request
    └── routes.py          (flask-restx Resource, input validation, rate limiting)
         └── orchestrator.py   (parallel fan-out via ThreadPoolExecutor)
              └── registry.py      (filter connectors by IoC type)
                   └── connectors/  (BaseConnector subclasses)
                        └── cti/verdicts.py  (normalize + aggregate)
    └── db/sqlite.py       (persist scan + provider results)
```

## Key Conventions

### Adding a CTI Provider
1. Create a class in `app/connectors/` that extends `BaseConnector`.
2. Set `name`, capability flags (`supports_ip`, etc.), and implement the corresponding `scan_*` methods.
3. Each `scan_*` method must return a dict with keys: `source`, `ioc`, `ioc_type`, `verdict`, `confidence`, `details`, `error`.
4. On failure, return `self._error_result(ioc, ioc_type, exc)` — never raise from a scan method.
5. Register the class in `AVAILABLE_CONNECTORS` in `app/connectors/registry.py`.

### Verdict Values
Only four valid verdicts: `"malicious"`, `"suspicious"`, `"clean"`, `"unknown"`. Use `normalize_verdict()` from `app/cti/verdicts.py` before storing or returning any verdict string.

### Configuration
All runtime config flows through `app/config.py` → `Config` class → `app.config`. Read values from `current_app.config` inside request context; read from `os.getenv()` inside connectors (they are instantiated outside app context).

### Database
Raw `sqlite3` — no ORM. Schema is defined as a SQL string in `app/db/sqlite.py`. All DB access goes through `init_db()` and `save_scan()`. The DB path is always taken from `app.config["SENTINEL_DB_PATH"]`.

### API Structure
- Blueprint mounted at `/api/scan` in `factory.py`.
- Namespaces defined in `routes.py`: `ip` → `/api/scan/ip`, `ioc` → `/api/scan/ioc`.
- Swagger models live in `models.py` and are registered against the `api` object from `blueprint.py`.
- Rate limiting applied per-route via `@limiter.limit(...)` decorator.
