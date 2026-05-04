"""AlienVault OTX v2 connector for threat intelligence scanning."""

import os

from OTXv2 import OTXv2, IndicatorTypes

from app.connectors.base import BaseConnector


class OTXConnector(BaseConnector):
    name = "OTXv2"
    supports_ip = True
    supports_domain = True
    supports_url = True
    supports_hash = True

    def __init__(self):
        api_key = os.getenv("OTX_API_KEY", "")
        if not api_key:
            raise RuntimeError("OTX_API_KEY is not set in environment.")
        self.client = OTXv2(api_key)

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_ip(self, ip: str) -> dict:
        try:
            general = self.client.get_indicator_details_by_section(
                IndicatorTypes.IPv4, ip, "general"
            )
            reputation = self.client.get_indicator_details_by_section(
                IndicatorTypes.IPv4, ip, "reputation"
            )
            geo = self.client.get_indicator_details_by_section(
                IndicatorTypes.IPv4, ip, "geo"
            )

            pulse_count = general.get("pulse_info", {}).get("count", 0)
            verdict, confidence = self._verdict_from_pulses(pulse_count)

            return {
                "source": self.name,
                "ioc": ip,
                "ioc_type": "ip",
                "verdict": verdict,
                "confidence": confidence,
                "details": {
                    "pulse_count": pulse_count,
                    "country": geo.get("country_name", "Unknown"),
                    "asn": geo.get("asn", "Unknown"),
                    "reputation": reputation.get("reputation", {}),
                },
                "error": None,
            }

        except Exception as exc:
            return self._error_result(ip, "ip", exc)

    def scan_domain(self, domain: str) -> dict:
        try:
            general = self.client.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, domain, "general"
            )

            pulse_count = general.get("pulse_info", {}).get("count", 0)
            verdict, confidence = self._verdict_from_pulses(pulse_count)

            return {
                "source": self.name,
                "ioc": domain,
                "ioc_type": "domain",
                "verdict": verdict,
                "confidence": confidence,
                "details": {
                    "pulse_count": pulse_count,
                    "alexa": general.get("alexa", "Unknown"),
                    "whois": general.get("whois", "Unknown"),
                },
                "error": None,
            }

        except Exception as exc:
            return self._error_result(domain, "domain", exc)

    def scan_url(self, url: str) -> dict:
        try:
            general = self.client.get_indicator_details_by_section(
                IndicatorTypes.URL, url, "general"
            )

            pulse_count = general.get("pulse_info", {}).get("count", 0)
            verdict, confidence = self._verdict_from_pulses(pulse_count)

            return {
                "source": self.name,
                "ioc": url,
                "ioc_type": "url",
                "verdict": verdict,
                "confidence": confidence,
                "details": {
                    "pulse_count": pulse_count,
                    "domain": general.get("domain", "Unknown"),
                    "hostname": general.get("hostname", "Unknown"),
                },
                "error": None,
            }

        except Exception as exc:
            return self._error_result(url, "url", exc)

    def scan_hash(self, file_hash: str) -> dict:
        try:
            general = self.client.get_indicator_details_by_section(
                IndicatorTypes.FILE_HASH_MD5, file_hash, "general"
            )

            pulse_count = general.get("pulse_info", {}).get("count", 0)
            verdict, confidence = self._verdict_from_pulses(pulse_count)

            return {
                "source": self.name,
                "ioc": file_hash,
                "ioc_type": "hash",
                "verdict": verdict,
                "confidence": confidence,
                "details": {
                    "pulse_count": pulse_count,
                    "file_type": general.get("type_title", "Unknown"),
                    "file_size": general.get("size", 0),
                    "md5": general.get("md5", ""),
                    "sha1": general.get("sha1", ""),
                    "sha256": general.get("sha256", ""),
                },
                "error": None,
            }

        except Exception as exc:
            return self._error_result(file_hash, "hash", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_from_pulses(count: int) -> tuple[str, float]:
        """Derive a verdict and confidence score from OTX pulse count."""
        if count == 0:
            return "clean", 0.1
        elif count <= 2:
            return "suspicious", 0.5
        return "malicious", min(0.5 + count * 0.05, 1.0)
