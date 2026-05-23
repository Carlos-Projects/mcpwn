from __future__ import annotations

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def connect_stdio(command: str, args: list[str] | None = None):
    params = StdioServerParameters(
        command=command,
        args=args or [],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def connect_http(url: str):
    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session