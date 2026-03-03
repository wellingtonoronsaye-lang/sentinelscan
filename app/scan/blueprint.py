from flask import Blueprint
from flask_restx import Api

scan_blueprint = Blueprint("scan", __name__)

api = Api(
    scan_blueprint,
    version="1.0",
    title="SentinelScan API",
    description="IoC scanning via threat intelligence sources",
    doc="/docs",
)