"""Verdict normalization and aggregation."""

VERDICT_PRIORITY = {
    "error": -1,
    "unknown": 0,
    "clean": 1,
    "suspicious": 2,
    "malicious": 3,
}


def normalize_verdict(verdict: str | None) -> str:
    normalized = (verdict or "unknown").strip().lower()
    if normalized not in VERDICT_PRIORITY:
        return "unknown"
    return normalized


def aggregate_verdict(results: list[dict]) -> str:
    if not results:
        return "unknown"
    return max(
        (normalize_verdict(result.get("verdict")) for result in results),
        key=lambda verdict: VERDICT_PRIORITY[verdict],
    )
