from app.connectors.base import BaseConnector

class VirustotalConnector(BaseConnector):
    name = "Virustotal-Connector"

    def scan_ip(self, ip: str) -> dict:
        pass

    def scan_domain(self, domain: str) -> dict:
        pass

    def scan_url(self, url: str) -> dict:
        pass