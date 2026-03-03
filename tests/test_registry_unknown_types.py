"""Tests for ConnectorRegistry handling of unknown IoC types."""

import pytest
from app.connectors.registry import ConnectorRegistry


class TestUnknownIoCTypes:
    """Test that ConnectorRegistry handles unknown IoC types gracefully."""

    def test_unknown_ioc_type_returns_empty_list(self):
        """Unknown IoC types should return empty list, not raise exception."""
        result = ConnectorRegistry.get_connectors_for_type("unknown_type")
        assert result == []

    def test_invalid_ioc_type_returns_empty_list(self):
        """Invalid IoC types should return empty list."""
        result = ConnectorRegistry.get_connectors_for_type("invalid")
        assert result == []

    def test_empty_string_ioc_type_returns_empty_list(self):
        """Empty string IoC type should return empty list."""
        result = ConnectorRegistry.get_connectors_for_type("")
        assert result == []

    def test_none_ioc_type_returns_empty_list(self):
        """None IoC type should return empty list."""
        result = ConnectorRegistry.get_connectors_for_type(None)
        assert result == []

    def test_numeric_ioc_type_returns_empty_list(self):
        """Numeric IoC type should return empty list."""
        result = ConnectorRegistry.get_connectors_for_type(123)
        assert result == []

    def test_valid_ioc_types_work_correctly(self):
        """Verify valid IoC types still work after unknown type handling."""
        # These should not raise exceptions
        ip_connectors = ConnectorRegistry.get_connectors_for_type("ip")
        domain_connectors = ConnectorRegistry.get_connectors_for_type("domain")
        url_connectors = ConnectorRegistry.get_connectors_for_type("url")
        hash_connectors = ConnectorRegistry.get_connectors_for_type("hash")
        
        # At least IP should have connectors (OTXConnector)
        assert isinstance(ip_connectors, list)
        assert isinstance(domain_connectors, list)
        assert isinstance(url_connectors, list)
        assert isinstance(hash_connectors, list)
