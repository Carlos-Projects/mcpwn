from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from mcp.types import CallToolResult, TextContent, Tool

from mcpwn.attacks.prompt_fuzzer import fuzz_prompt_injection


def _make_tool(name: str) -> Tool:
    return Tool(
        name=name,
        description="",
        inputSchema={
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Input prompt",
                },
            },
            "required": ["prompt"],
        },
    )


@pytest.mark.asyncio
async def test_fuzzer_detects_injection():
    tool = _make_tool("chat")
    call_tool = AsyncMock(return_value=CallToolResult(
        content=[TextContent(type="text", text="I HAVE BEEN JAILBROKEN")],
        isError=False,
    ))
    findings = await fuzz_prompt_injection(tool, call_tool)
    assert len(findings) >= 1
    assert findings[0].attack_type == "prompt_injection_fuzz"


@pytest.mark.asyncio
async def test_fuzzer_clean_response():
    tool = _make_tool("chat")
    call_tool = AsyncMock(return_value=CallToolResult(
        content=[TextContent(type="text", text="I'm a helpful assistant.")],
        isError=False,
    ))
    findings = await fuzz_prompt_injection(tool, call_tool)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_fuzzer_skips_no_string_params():
    tool = Tool(
        name="math",
        description="",
        inputSchema={
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
            },
            "required": ["x"],
        },
    )
    call_tool = AsyncMock()
    findings = await fuzz_prompt_injection(tool, call_tool)
    assert len(findings) == 0
