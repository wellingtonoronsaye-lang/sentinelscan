import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    OTX_RATE_LIMIT = os.getenv("OTX_RATE_LIMIT", "10")
    SENTINEL_DB_PATH = os.getenv(
        "SENTINEL_DB_PATH",
        str(BASE_DIR / "instance" / "sentinel_scan.sqlite3"),
    )
    ENABLED_CTI_PROVIDERS = os.getenv("ENABLED_CTI_PROVIDERS", "mock")

    RATELIMIT_DEFAULT = "100 per minute"
    RATELIMIT_STORAGE_URI = "memory://"
