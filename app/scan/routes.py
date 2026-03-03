import concurrent.futures

from flask import current_app
from flask_restx import Resource

from app.scan.blueprint import api
from app.scan.models import scan_request, scan_response
from app.connectors.registry import CONNECTORS
from app.extensions import limiter

ns = api.namespace("ip", description="IP address scanning")


def _run_connectors(ip: str) -> list[dict]:
    """Instantiate and run all connectors in parallel."""
    def _scan(connector_cls):
        return connector_cls().scan_ip(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(CONNECTORS)) as pool:
        futures = [pool.submit(_scan, cls) for cls in CONNECTORS]
        return [f.result() for f in concurrent.futures.as_completed(futures)]


def _aggregate_verdict(results: list[dict]) -> str:
    """Highest-severity verdict wins across all sources."""
    priority = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    return max(results, key=lambda r: priority.get(r["verdict"], 0))["verdict"]


@ns.route("/scan")
class IPScan(Resource):

    @ns.expect(scan_request, validate=True)
    @ns.marshal_with(scan_response, code=200)
    @ns.response(400, "Validation Error")
    @ns.response(429, "Rate limit exceeded")
    @limiter.limit(lambda: f"{current_app.config.get('OTX_RATE_LIMIT', 10)} per minute")
    def post(self):
        """Submit an IP address for threat intelligence scanning."""
        ip = api.payload["ip"].strip()
        results = _run_connectors(ip)

        return {
            "ioc":             ip,
            "ioc_type":        "ip",
            "overall_verdict": _aggregate_verdict(results),
            "sources_scanned": len(results),
            "results":         results,
        }, 200