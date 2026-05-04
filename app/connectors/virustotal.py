"""VirusTotal v3 API connector for threat intelligence scanning."""

import base64
import os

import requests

from app.connectors.base import BaseConnector

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirustotalConnector(BaseConnector):
    name = "VirusTotal"
    supports_ip = True
    supports_domain = True
    supports_url = True
    supports_hash = True

    def __init__(self):
        api_key = os.getenv("VT_API_KEY", "")
        if not api_key:
            raise RuntimeError("VT_API_KEY is not set in environment.")
        self._headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Public scan methods
    # ------------------------------------------------------------------

    def scan_ip(self, ip: str) -> dict:
        try:
            data = self._get(f"/ip_addresses/{ip}")
            return self._build_result(ip, "ip", data)
        except Exception as exc:
            return self._error_result(ip, "ip", exc)

    def scan_domain(self, domain: str) -> dict:
        try:
            data = self._get(f"/domains/{domain}")
            return self._build_result(domain, "domain", data)
        except Exception as exc:
            return self._error_result(domain, "domain", exc)

    def scan_url(self, url: str) -> dict:
        try:
            # VT v3 uses a URL-safe base64 identifier (no padding) for URLs.
            url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
            data = self._get(f"/urls/{url_id}")
            return self._build_result(url, "url", data)
        except Exception as exc:
            return self._error_result(url, "url", exc)

    def scan_hash(self, file_hash: str) -> dict:
        try:
            data = self._get(f"/files/{file_hash}")
            return self._build_result(file_hash, "hash", data)
        except Exception as exc:
            return self._error_result(file_hash, "hash", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> dict:
        """Perform a GET request against the VT v3 API and return parsed JSON."""
        response = requests.get(
            f"{_VT_BASE}{path}",
            headers=self._headers,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()

    def _build_result(self, ioc: str, ioc_type: str, data: dict) -> dict:
        """Convert a VT API response into the standard connector result dict."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        verdict, confidence = self._verdict_from_stats(malicious, suspicious, total)

        details = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
        }

        # Attach type-specific metadata when available.
        if ioc_type == "ip":
            details["country"] = attrs.get("country", "Unknown")
            details["asn"] = attrs.get("asn", "Unknown")
            details["as_owner"] = attrs.get("as_owner", "Unknown")
            details["reputation"] = attrs.get("reputation", 0)
        elif ioc_type == "domain":
            details["registrar"] = attrs.get("registrar", "Unknown")
            details["reputation"] = attrs.get("reputation", 0)
            details["categories"] = attrs.get("categories", {})
        elif ioc_type == "url":
            details["final_url"] = attrs.get("last_final_url", ioc)
            details["title"] = attrs.get("title", "")
            details["reputation"] = attrs.get("reputation", 0)
        elif ioc_type == "hash":
            details["file_type"] = attrs.get("type_description", "Unknown")
            details["file_size"] = attrs.get("size", 0)
            details["meaningful_name"] = attrs.get("meaningful_name", "")
            details["tags"] = attrs.get("tags", [])

        return {
            "source": self.name,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "verdict": verdict,
            "confidence": confidence,
            "details": details,
            "error": None,
        }

    @staticmethod
    def _verdict_from_stats(malicious: int, suspicious: int, total: int) -> tuple[str, float]:
        """Derive a verdict and confidence score from VT engine stats."""
        if total == 0:
            return "unknown", 0.0

        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total

        if malicious >= 3 or malicious_ratio >= 0.10:
            confidence = min(0.5 + malicious_ratio, 1.0)
            return "malicious", round(confidence, 4)

        if malicious >= 1 or suspicious >= 2 or suspicious_ratio >= 0.05:
            confidence = round(0.3 + (malicious + suspicious) / total * 0.5, 4)
            return "suspicious", min(confidence, 0.9)

        return "clean", round(max(0.1, 1.0 - (malicious + suspicious) / total), 4)
