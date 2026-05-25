from __future__ import annotations

from mcp.types import Tool, TextContent

from mcpwn.core.findings import Finding

SSRF_PAYLOADS = [
    ("localhost_port", "http://127.0.0.1:22"),
    ("localhost_http", "http://127.0.0.1:80"),
    ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
    ("internal_dns", "http://internal.corp.local/"),
    ("file_protocol", "file:///etc/passwd"),
]


async def scan_ssrf(tool: Tool, call_tool_fn) -> list[Finding]:
    findings: list[Finding] = []
    input_schema = tool.inputSchema or {}
    properties = input_schema.get("properties", {})

    for param_name, param_schema in properties.items():
        if isinstance(param_schema, dict) and param_schema.get("type") == "string":
            desc = (param_schema.get("description") or "").lower()
            if any(kw in desc for kw in ["url", "uri", "link", "endpoint", "host", "fetch", "get"]):
                for payload_name, payload in SSRF_PAYLOADS:
                    try:
                        result = await call_tool_fn(tool.name, {param_name: payload})
                        content = result.content if result else []
                        for c in content:
                            if isinstance(c, TextContent) and c.text:
                                text_lower = c.text.lower()
                                if any(sig in text_lower for sig in ["connection refused", "connection timed out", "no route to host", "name or service not known"]):
                                    findings.append(Finding(
                                        id=f"SSRF-{tool.name}-{param_name}-{payload_name}",
                                        title=f"SSRF detected in '{tool.name}.{param_name}' via {payload_name}",
                                        severity="high",
                                        attack_type="ssrf",
                                        target=f"{tool.name}.{param_name}",
                                        description=f"Parameter '{param_name}' accepted a URL pointing to internal service ({payload_name}). The server attempted to connect.",
                                        detail=f"Payload: {payload}\nResponse indicates network activity to internal address.",
                                        recommendation="Restrict tool to allowlisted URLs only. Block private IP ranges and internal hostnames.",
                                        evidence={
                                            "tool": tool.name,
                                            "parameter": param_name,
                                            "payload": payload,
                                            "response_preview": c.text[:200],
                                        },
                                    ))
                                    break
                    except Exception:
                        continue

    return findings