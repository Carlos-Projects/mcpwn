from __future__ import annotations

import asyncio
import time

from mcp.types import Tool

from mcpwn.core.findings import Finding

RCE_PAYLOADS = [
    ("sleep_3", "; sleep 3"),
    ("ping_loop", "&& ping -c 3 127.0.0.1"),
    ("subshell_sleep", "$(sleep 3)"),
    ("backtick_sleep", "`sleep 3`"),
]

BASELINE_TIMEOUT = 0.5
THRESHOLD = 2.0


async def scan_rce_blind(tool: Tool, call_tool_fn) -> list[Finding]:
    findings: list[Finding] = []
    input_schema = tool.inputSchema or {}
    properties = input_schema.get("properties", {})

    for param_name, param_schema in properties.items():
        if isinstance(param_schema, dict) and param_schema.get("type") == "string":
            for payload_name, payload in RCE_PAYLOADS:
                try:
                    start = time.monotonic()
                    result = await asyncio.wait_for(call_tool_fn(tool.name, {param_name: payload}), timeout=15)
                    elapsed = time.monotonic() - start

                    if elapsed >= THRESHOLD and not getattr(result, "isError", False):
                        findings.append(Finding(
                            id=f"RCE-BLIND-{tool.name}-{param_name}-{payload_name}",
                            title=f"Blind RCE detected in '{tool.name}.{param_name}' (timing: {elapsed:.1f}s)",
                            severity="critical",
                            attack_type="rce_blind",
                            target=f"{tool.name}.{param_name}",
                            description=f"Parameter '{param_name}' caused a {elapsed:.1f}s delay with payload '{payload_name}', suggesting command execution.",
                            detail=f"Payload: {payload}\nResponse time: {elapsed:.1f}s (threshold: {THRESHOLD}s)",
                            recommendation="Sanitize all user input before passing to shell. Use subprocess with argument lists.",
                            evidence={
                                "tool": tool.name,
                                "parameter": param_name,
                                "payload": payload,
                                "response_time": round(elapsed, 2),
                            },
                        ))
                        break
                except Exception:
                    continue

    return findings
