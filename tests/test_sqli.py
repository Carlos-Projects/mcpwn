from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.types import CallToolResult, TextContent, Tool

from mcpwn.attacks.sqli_tester import scan_sql_injection


def _make_tool(name: str, param_desc: str) -> Tool:
    return Tool(
        name=name,
        description="",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": param_desc,
                },
            },
            "required": ["query"],
        },
    )


@pytest.mark.asyncio
async def test_sqli_finds_injection():
    tool = _make_tool("search_db", "SQL query to search the database")
    call_tool = AsyncMock(return_value=CallToolResult(
        content=[TextContent(type="text", text='{"columns": ["id","name","password"], "rows": [[1,"admin","p@ssw0rd"]]}')],
        isError=False,
    ))
    findings = await scan_sql_injection(tool, call_tool)
    assert len(findings) >= 1
    assert findings[0].attack_type == "sql_injection"


@pytest.mark.asyncio
async def test_sqli_no_keyword_skip():
    tool = _make_tool("echo", "just echoes input")
    call_tool = AsyncMock()
    findings = await scan_sql_injection(tool, call_tool)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_sqli_clean_response_no_finding():
    tool = _make_tool("search_db", "SQL query to search")
    call_tool = AsyncMock(return_value=CallToolResult(
        content=[TextContent(type="text", text="no sensitive data here")],
        isError=False,
    ))
    findings = await scan_sql_injection(tool, call_tool)
    assert len(findings) == 0
