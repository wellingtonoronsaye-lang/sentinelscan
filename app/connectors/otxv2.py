import os

from OTXv2 import OTXv2, IndicatorTypes

from app.connectors.base import BaseConnector


class OTXConnector(BaseConnector):
    name = "OTXv2"

    def __init__(self):
        api_key = os.getenv("OTX_API_KEY", "")
        if not api_key:
            raise RuntimeError("OTX_API_KEY is not set in environment.")
        self.client = OTXv2(api_key)

    def scan_ip(self, ip: str) -> dict:
        try:
            general    = self.client.get_indicator_details_by_section(
                            IndicatorTypes.IPv4, ip, "general")
            reputation = self.client.get_indicator_details_by_section(
                            IndicatorTypes.IPv4, ip, "reputation")
            geo        = self.client.get_indicator_details_by_section(
                            IndicatorTypes.IPv4, ip, "geo")

            pulse_count = general.get("pulse_info", {}).get("count", 0)
            verdict, confidence = self._verdict_from_pulses(pulse_count)

            return {
                "source":     self.name,
                "ioc":        ip,
                "ioc_type":   "ip",
                "verdict":    verdict,
                "confidence": confidence,
                "details": {
                    "pulse_count": pulse_count,
                    "country":     geo.get("country_name", "Unknown"),
                    "asn":         geo.get("asn", "Unknown"),
                    "reputation":  reputation.get("reputation", {}),
                },
                "error": None,
            }

        except Exception as exc:
            return self._error_result(ip, exc)

    @staticmethod
    def _verdict_from_pulses(count: int) -> tuple[str, float]:
        if count == 0:
            return "clean", 0.1
        elif count <= 2:
            return "suspicious", 0.5
        return "malicious", min(0.5 + count * 0.05, 1.0)