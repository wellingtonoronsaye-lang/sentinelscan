"""Development CTI provider used until real provider API keys are configured."""

from app.connectors.base import BaseConnector


class MockProvider(BaseConnector):
    name = "MockCTI"
    supports_ip = True
    supports_domain = True
    supports_url = True
    supports_hash = True

    def scan_ip(self, ip: str) -> dict:
        return self._scan(ioc=ip, ioc_type="ip")

    def scan_domain(self, domain: str) -> dict:
        return self._scan(ioc=domain, ioc_type="domain")

    def scan_url(self, url: str) -> dict:
        return self._scan(ioc=url, ioc_type="url")

    def scan_hash(self, file_hash: str) -> dict:
        return self._scan(ioc=file_hash, ioc_type="hash")

    def _scan(self, *, ioc: str, ioc_type: str) -> dict:
        lowered = ioc.lower()
        verdict = "malicious" if "malware" in lowered or "evil" in lowered else "clean"
        confidence = 0.9 if verdict == "malicious" else 0.2

        return {
            "source": self.name,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "verdict": verdict,
            "confidence": confidence,
            "details": {
                "reason": "Development-only deterministic mock result",
                "matched_terms": [
                    term for term in ("malware", "evil") if term in lowered
                ],
            },
            "error": None,
        }
