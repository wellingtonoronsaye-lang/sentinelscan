from flask import Flask
from dotenv import load_dotenv

from app.config import Config
from app.extensions import limiter
from app.scan.blueprint import scan_blueprint


def create_app() -> Flask:
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(Config)

    limiter.init_app(app)

    app.register_blueprint(scan_blueprint, url_prefix="/api/scan")

    return app