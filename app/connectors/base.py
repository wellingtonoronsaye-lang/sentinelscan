from abc import ABC, abstractmethod


class BaseConnector(ABC):
    name: str = "base"

    # Capability flags - override in subclasses
    supports_ip: bool = False
    supports_domain: bool = False
    supports_url: bool = False
    supports_hash: bool = False

    @abstractmethod
    def scan_ip(self, ip: str) -> dict:
        pass

    @abstractmethod
    def scan_domain(self, domain: str) -> dict:
        pass

    @abstractmethod
    def scan_url(self, url: str) -> dict:
        pass

    @abstractmethod
    def scan_hash(self, file_hash: str) -> dict:
        pass


    def _error_result(self, ioc: str, ioc_type: str, exc: Exception) -> dict:
            return {
                "source":     self.name,
                "ioc":        ioc,
                "ioc_type":   ioc_type,
                "verdict":    "unknown",
                "confidence": 0.0,
                "details":    {},
                "error":      str(exc),
            }

