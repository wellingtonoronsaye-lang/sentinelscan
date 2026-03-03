from abc import ABC, abstractmethod


class BaseConnector(ABC):
    name: str = "base"

    @abstractmethod
    def scan_ip(self, ip: str) -> dict:
        pass

    def _error_result(self, ip: str, exc: Exception) -> dict:
        return {
            "source":     self.name,
            "ioc":        ip,
            "ioc_type":   "ip",
            "verdict":    "unknown",
            "confidence": 0.0,
            "details":    {},
            "error":      str(exc),
        }