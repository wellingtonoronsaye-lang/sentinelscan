import os

from flask import Flask
from dotenv import load_dotenv

from app.config import Config
from app.db.sqlite import init_db
from app.extensions import limiter
from app.scan.blueprint import scan_blueprint
import app.scan.routes  # noqa: F401  Ensures REST namespaces are registered.


def create_app() -> Flask:
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["SENTINEL_DB_PATH"] = os.getenv(
        "SENTINEL_DB_PATH",
        app.config["SENTINEL_DB_PATH"],
    )
    app.config["ENABLED_CTI_PROVIDERS"] = os.getenv(
        "ENABLED_CTI_PROVIDERS",
        app.config["ENABLED_CTI_PROVIDERS"],
    )

    limiter.init_app(app)
    init_db(app.config["SENTINEL_DB_PATH"])

    app.register_blueprint(scan_blueprint, url_prefix="/api/scan")

    return app
