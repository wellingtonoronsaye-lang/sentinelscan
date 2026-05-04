"""Registry for enabled CTI provider plugins."""

from __future__ import annotations

import os
from typing import List, Type

from app.connectors.base import BaseConnector
from app.connectors.otxv2 import OTXConnector
from app.connectors.virustotal import VirustotalConnector
from app.plugins.mock_provider import MockProvider


AVAILABLE_CONNECTORS = {
    "mock": MockProvider,
    "otx": OTXConnector,
    "otxv2": OTXConnector,
    "virustotal": VirustotalConnector,
    "vt": VirustotalConnector,
}


def _enabled_connector_names() -> list[str]:
    configured = os.getenv("ENABLED_CTI_PROVIDERS", "mock")
    return [
        name.strip().lower()
        for name in configured.split(",")
        if name.strip()
    ]


def get_enabled_connectors() -> list[Type[BaseConnector]]:
    """Return enabled connector classes in configured order."""
    connectors: list[Type[BaseConnector]] = []
    for name in _enabled_connector_names():
        connector = AVAILABLE_CONNECTORS.get(name)
        if connector and connector not in connectors:
            connectors.append(connector)
    return connectors


# Backwards-compatible module constant for old imports.
CONNECTORS = get_enabled_connectors()


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

        attr = capability_map.get(ioc_type)
        if not attr:
            return []

        return [
            connector for connector in get_enabled_connectors()
            if getattr(connector, attr, False)
        ]
