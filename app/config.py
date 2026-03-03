import os


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    OTX_RATE_LIMIT = os.getenv("OTX_RATE_LIMIT", "10")

    RATELIMIT_DEFAULT = "100 per minute"
    RATELIMIT_STORAGE_URI = "memory://"