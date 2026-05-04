from flask import current_app
from flask_restx import Resource

from app.cti.verdicts import aggregate_verdict
from app.db.sqlite import save_scan
from app.extensions import limiter
from app.scan.blueprint import api
from app.scan.models import generic_scan_request, scan_request, scan_response
from app.scan.orchestrator import run_connectors

ns = api.namespace("ip", description="IP address scanning")
generic_ns = api.namespace("ioc", description="Generic IoC scanning")


def _scan_and_save(ioc: str, ioc_type: str) -> dict:
    results = run_connectors(ioc, ioc_type)
    overall_verdict = aggregate_verdict(results)
    scan_id = save_scan(
        current_app.config["SENTINEL_DB_PATH"],
        ioc=ioc,
        ioc_type=ioc_type,
        overall_verdict=overall_verdict,
        results=results,
    )

    return {
        "scan_id": scan_id,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "overall_verdict": overall_verdict,
        "sources_scanned": len(results),
        "results": results,
    }


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
        return _scan_and_save(ip, "ip"), 200


@generic_ns.route("/scan")
class IoCScan(Resource):

    @generic_ns.expect(generic_scan_request, validate=True)
    @generic_ns.marshal_with(scan_response, code=200)
    @generic_ns.response(400, "Validation Error")
    @generic_ns.response(429, "Rate limit exceeded")
    @limiter.limit(lambda: f"{current_app.config.get('OTX_RATE_LIMIT', 10)} per minute")
    def post(self):
        """Submit any supported IoC type for threat intelligence scanning."""
        payload = api.payload
        ioc = payload["ioc"].strip()
        ioc_type = payload["ioc_type"].strip().lower()
        if ioc_type not in {"ip", "domain", "url", "hash"}:
            api.abort(400, "ioc_type must be one of: ip, domain, url, hash")

        return _scan_and_save(ioc, ioc_type), 200
