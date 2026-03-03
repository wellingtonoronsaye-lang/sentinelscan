from typing import List, Type
from app.connectors.base import BaseConnector
from app.connectors.otxv2 import OTXConnector

# Add new connectors here — they auto-run in parallel
CONNECTORS = [
    OTXConnector,
]


class ConnectorRegistry:
    """Registry for managing and filtering threat intelligence connectors."""

    @staticmethod
    def get_connectors_for_type(ioc_type: str) -> List[Type[BaseConnector]]:
        """
        Filter connectors that support the specified IoC type.

        Args:
            ioc_type: One of 'ip', 'domain', 'url', 'hash'

        Returns:
            List of connector classes that support the IoC type.
            Returns empty list for unknown or unsupported IoC types.
        """
        capability_map = {
            "ip": "supports_ip",
            "domain": "supports_domain",
            "url": "supports_url",
            "hash": "supports_hash",
        }

        # Handle unknown IoC types gracefully by returning empty list
        attr = capability_map.get(ioc_type)
        if not attr:
            return []

        return [
            connector for connector in CONNECTORS
            if getattr(connector, attr, False)
        ]