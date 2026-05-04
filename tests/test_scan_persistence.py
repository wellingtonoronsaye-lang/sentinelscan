import sqlite3
from pathlib import Path
from uuid import uuid4

from app.factory import create_app


def _test_db_path() -> Path:
    return Path("instance") / f"test-{uuid4().hex}.sqlite3"


def test_generic_ioc_scan_saves_results(monkeypatch):
    db_path = _test_db_path()
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db_path))
    monkeypatch.setenv("ENABLED_CTI_PROVIDERS", "mock")

    app = create_app()
    client = app.test_client()

    response = client.post(
        "/api/scan/ioc/scan",
        json={"ioc": "evil.example", "ioc_type": "domain"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scan_id"] == 1
    assert payload["overall_verdict"] == "malicious"
    assert payload["sources_scanned"] == 1

    with sqlite3.connect(db_path) as conn:
        scan_count = conn.execute("SELECT COUNT(*) FROM ioc_scans").fetchone()[0]
        result = conn.execute(
            "SELECT provider, verdict FROM provider_results"
        ).fetchone()

    assert scan_count == 1
    assert result == ("MockCTI", "malicious")


def test_unknown_ioc_type_is_rejected(monkeypatch):
    db_path = _test_db_path()
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db_path))
    monkeypatch.setenv("ENABLED_CTI_PROVIDERS", "mock")

    app = create_app()
    client = app.test_client()

    response = client.post(
        "/api/scan/ioc/scan",
        json={"ioc": "example", "ioc_type": "email"},
    )

    assert response.status_code == 400
