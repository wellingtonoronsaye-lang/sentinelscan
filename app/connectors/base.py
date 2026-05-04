from abc import ABC


class BaseConnector(ABC):
    name: str = "base"

    # Capability flags - override in subclasses
    supports_ip: bool = False
    supports_domain: bool = False
    supports_url: bool = False
    supports_hash: bool = False

    def scan_ip(self, ip: str) -> dict:
        return self._unsupported_result(ip, "ip")

    def scan_domain(self, domain: str) -> dict:
        return self._unsupported_result(domain, "domain")

    def scan_url(self, url: str) -> dict:
        return self._unsupported_result(url, "url")

    def scan_hash(self, file_hash: str) -> dict:
        return self._unsupported_result(file_hash, "hash")

    @classmethod
    def error_result(cls, ioc: str, ioc_type: str, exc: Exception) -> dict:
        return {
            "source": cls.name,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "verdict": "unknown",
            "confidence": 0.0,
            "details": {},
            "error": str(exc),
        }

    def _error_result(self, ioc: str, ioc_type: str, exc: Exception) -> dict:
        return self.error_result(ioc, ioc_type, exc)

    def _unsupported_result(self, ioc: str, ioc_type: str) -> dict:
        return {
            "source": self.name,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "verdict": "unknown",
            "confidence": 0.0,
            "details": {},
            "error": f"{self.name} does not support {ioc_type} scans.",
        }

