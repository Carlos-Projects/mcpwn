"""Adapter: MCPwn -> mcp-taxonomy."""

from mcp_taxonomy import mcpwn_finding_to_taxonomy as _normalize


def normalize_finding(finding) -> dict:
    """Convert a MCPwn Finding (dict or object) to a normalized taxonomy dict."""
    tax = _normalize(finding)
    return {
        "source": tax.source,
        "attack_category": tax.attack_category.value,
        "severity": tax.severity.value,
        "confidence": tax.confidence.value,
        "detection_method": tax.detection_method.value if hasattr(tax.detection_method, 'value') else str(tax.detection_method),
        "title": tax.title,
        "description": tax.description,
        "recommendation": tax.recommendation,
        "target": tax.target,
        "risk_score": tax.risk_score,
    }
