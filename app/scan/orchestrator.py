"""Parallel orchestrator for executing threat intelligence connectors."""

import concurrent.futures
from typing import List

from app.connectors.registry import ConnectorRegistry
from app.cti.verdicts import normalize_verdict


class ParallelOrchestrator:
    """Orchestrates parallel execution of threat intelligence connectors."""

    @staticmethod
    def run_connectors(ioc: str, ioc_type: str) -> List[dict]:
        """
        Execute all applicable connectors in parallel.

        Args:
            ioc: Indicator of compromise value
            ioc_type: Type of IoC ('ip', 'domain', 'url', 'hash')

        Returns:
            List of result dictionaries from all connectors

        Preconditions:
            - ioc is non-empty string
            - ioc_type is one of: 'ip', 'domain', 'url', 'hash'

        Postconditions:
            - Returns list of result dictionaries
            - Each result contains required keys: source, ioc, ioc_type, verdict,
              confidence, details, error
            - List length equals number of connectors supporting the IoC type
            - All connectors execute in parallel (no sequential blocking)
            - Failed connectors return error results (verdict='unknown',
              error message populated)
        """
        connectors = ConnectorRegistry.get_connectors_for_type(ioc_type)

        if not connectors:
            return []

        def _scan(connector_cls):
            """Execute scan for a single connector with error handling."""
            try:
                instance = connector_cls()
                scan_method = getattr(instance, f"scan_{ioc_type}")
                result = scan_method(ioc)
                result["verdict"] = normalize_verdict(result.get("verdict"))
                return result
            except Exception as exc:
                return connector_cls.error_result(ioc, ioc_type, exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(connectors)) as pool:
            futures = [pool.submit(_scan, cls) for cls in connectors]
            return [f.result() for f in concurrent.futures.as_completed(futures)]



# Convenience function for backward compatibility
def run_connectors(ioc: str, ioc_type: str) -> List[dict]:
    """
    Execute all applicable connectors in parallel.
    
    This is a convenience wrapper around ParallelOrchestrator.run_connectors()
    for backward compatibility.
    
    Args:
        ioc: Indicator of compromise value
        ioc_type: Type of IoC ('ip', 'domain', 'url', 'hash')
        
    Returns:
        List of result dictionaries from all connectors
    """
    return ParallelOrchestrator.run_connectors(ioc, ioc_type)
