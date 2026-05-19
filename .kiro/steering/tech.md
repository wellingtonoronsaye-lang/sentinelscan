# Tech Stack & Build System

## Runtime
- **Python** ≥ 3.14 (pinned via `.python-version`)
- **Package manager**: `uv` — use `uv sync` to install deps, `uv run` to execute

## Key Dependencies
| Package | Role |
|---------|------|
| `flask` ≥ 3.1 | Web framework |
| `flask-restx` ≥ 1.3 | REST API + Swagger UI |
| `flask-limiter` ≥ 4.1 | Rate limiting (in-memory by default) |
| `python-dotenv` | `.env` loading |
| `requests` | HTTP client (VirusTotal connector) |
| `otxv2` | AlienVault OTX SDK |
| `pytest` | Test runner |
| `ruff` | Linter / formatter |

All dependencies are declared in `pyproject.toml` with minimum-version pins. Use exact or minimum-version pins — avoid open-ended ranges.

## Environment Configuration
Copy `.env-example` → `.env` before running. Key variables:

```
FLASK_SECRET_KEY=
ENABLED_CTI_PROVIDERS=mock          # comma-separated: mock, otx, virustotal
SENTINEL_DB_PATH=instance/sentinel_scan.sqlite3
OTX_API_KEY=
OTX_RATE_LIMIT=10
VT_API_KEY=
URL_SCAN_API_KEY=
```

Flask dev settings live in `.flaskenv` (`FLASK_APP=run.py`, `FLASK_ENV=debug`, `FLASK_PORT=5000`).

## Common Commands

```powershell
# Install dependencies
uv sync

# Run development server
cd .\Documents\CSO\soc_analysis\; Set-Alias -name uv -value C:\Users\wellingtonoronsaye\tools\uv.exe; uv run python run.py
# or, if uv is unavailable:
.\.venv\Scripts\python.exe run.py

# Run tests (single pass, no watch mode)
.\.venv\Scripts\python.exe -m pytest tests -p no:cacheprovider

# Lint
.\.venv\Scripts\python.exe -m ruff check app tests

# Format
.\.venv\Scripts\python.exe -m ruff format app tests
```

## Testing Conventions
- Tests live in `tests/`, one file per concern.
- Each test that needs a database creates its own isolated SQLite file via `_test_db_path()` (UUID-named under `instance/`).
- Use `monkeypatch.setenv` to override `SENTINEL_DB_PATH` and `ENABLED_CTI_PROVIDERS` per test — never mutate global state.
- Use `app.test_client()` for HTTP-level integration tests; import domain modules directly for unit tests.
- No test fixtures file yet — keep helpers as module-level functions within the test file.
