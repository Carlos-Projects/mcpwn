from __future__ import annotations

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from rich.console import Console


@asynccontextmanager
async def connect_stdio(command: str, args: list[str] | None = None, yes: bool = False):
    cmd_display = command + (" " + " ".join(args) if args else "")
    if not yes:
        Console().print(f"\n[bold red][!] WARNING: About to execute arbitrary command: {cmd_display}[/]")
        Console().print("[bold yellow][!] Only proceed if you trust this command.[/]")
        Console().print("[bold yellow][!] Use --yes to skip this warning.[/]\n")
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
