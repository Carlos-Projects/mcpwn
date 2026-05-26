from __future__ import annotations

import asyncio
from typing import Any

from mcp.types import TextContent, Tool

from mcpwn.core.findings import Finding

INJECTION_PAYLOADS = [
    ("semicolon", "; echo MCPWN_SECURITY_TEST"),
    ("and", "&& echo MCPWN_SECURITY_TEST"),
    ("pipe", "| echo MCPWN_SECURITY_TEST"),
    ("dollar_subshell", "$(echo MCPWN_SECURITY_TEST)"),
    ("backtick", "`echo MCPWN_SECURITY_TEST`"),
]

DETECTION_MARKER = "MCPWN_SECURITY_TEST"

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "../../../../Windows/System32/drivers/etc/hosts",
]


async def test_command_injection(
    tool: Tool,
    call_tool_fn,
) -> list[Finding]:
    findings: list[Finding] = []
    input_schema = tool.inputSchema or {}
    properties = input_schema.get("properties", {})
    required = input_schema.get("required", [])

    if not properties:
        return findings

    commands: dict[str, str | None] = {}
    for param_name, param_schema in properties.items():
        if isinstance(param_schema, dict) and param_schema.get("type") == "string":
            commands[param_name] = None

    if not commands:
        return findings

    for param_name in commands:
        for payload_name, payload in INJECTION_PAYLOADS:
            try:
                arguments: dict[str, Any] = {}
                for p in properties:
                    if p == param_name:
                        arguments[p] = payload
                    elif p in required:
                        p_schema = properties[p]
                        match p_schema.get("type"):
                            case "string":
                                arguments[p] = "test"
                            case "integer" | "number":
                                arguments[p] = 1
                            case "boolean":
                                arguments[p] = False
                            case _:
                                arguments[p] = "test"
                    else:
                        pass

                result = await asyncio.wait_for(
                    call_tool_fn(tool.name, arguments), timeout=15
                )

                if result and not result.isError:
                    for c in result.content or []:
                        if isinstance(c, TextContent) and DETECTION_MARKER in (
                            c.text or ""
                        ):
                            findings.append(
                                Finding(
                                    id=f"INJECT-CMD-{tool.name}-{param_name}-{payload_name}",
                                    title=f"Command injection detected in '{tool.name}.{param_name}'",
                                    severity="critical",
                                    attack_type="command_injection",
                                    target=f"{tool.name}.{param_name}",
                                    description=f"Parameter '{param_name}' of tool '{tool.name}' is vulnerable to {payload_name} command injection.",
                                    detail=f"Payload: {payload}\nThe marker '{DETECTION_MARKER}' appeared in the tool response, confirming arbitrary command execution.",
                                    recommendation="Sanitize all user input before passing to shell commands. Use subprocess with argument lists instead of shell=True. Avoid constructing shell commands from user input entirely.",
                                    evidence={
                                        "tool": tool.name,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "payload_type": payload_name,
                                    },
                                )
                            )
                            break
            except Exception:
                continue

    return findings


async def test_path_traversal(
    tool: Tool,
    call_tool_fn,
) -> list[Finding]:
    findings: list[Finding] = []
    input_schema = tool.inputSchema or {}
    properties = input_schema.get("properties", {})

    for param_name, param_schema in properties.items():
        if isinstance(param_schema, dict) and param_schema.get("type") == "string":
            desc = (param_schema.get("description") or "").lower()
            if any(kw in desc for kw in ["path", "file", "dir", "folder", "location"]):
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    try:
                        result = await asyncio.wait_for(
                            call_tool_fn(tool.name, {param_name: payload}), timeout=15
                        )
                        content = result.content if result else []
                        for c in content:
                            if (
                                isinstance(c, TextContent)
                                and c.text
                                and len(c.text) > 20
                            ):
                                if (
                                    "root:" in c.text
                                    or "localhost" in c.text
                                    or "[extensions]" in c.text
                                ):
                                    findings.append(
                                        Finding(
                                            id=f"INJECT-PATH-{tool.name}-{param_name}",
                                            title=f"Path traversal detected in '{tool.name}.{param_name}'",
                                            severity="critical",
                                            attack_type="path_traversal",
                                            target=f"{tool.name}.{param_name}",
                                            description=f"Parameter '{param_name}' is vulnerable to path traversal.",
                                            detail=f"Payload: {payload}\nThe response contained contents of a system file.",
                                            recommendation="Validate and sanitize file paths. Use allowlist of permitted directories. Reject paths containing '..' or absolute paths.",
                                            evidence={
                                                "tool": tool.name,
                                                "parameter": param_name,
                                                "payload": payload,
                                            },
                                        )
                                    )
                                    break
                    except Exception:
                        continue

    return findings
