from contextlib import asynccontextmanager

import httpx
import pytest
from typer.testing import CliRunner

from mcpwn import cli
from mcpwn.core.findings import ScanResult
from mcpwn.utils import mcp_connect


def test_survey_passes_timeout_to_runner(monkeypatch):
    captured = {}

    async def fake_run_survey(**kwargs):
        captured.update(kwargs)
        return ScanResult(target=kwargs["url"])

    monkeypatch.setattr(cli, "run_survey", fake_run_survey)

    result = CliRunner().invoke(
        cli.app,
        ["survey", "--url", "http://example.com/mcp", "--timeout", "7.5"],
    )

    assert result.exit_code == 0
    assert captured["timeout"] == 7.5


def test_survey_rejects_non_positive_timeout():
    result = CliRunner().invoke(
        cli.app,
        ["survey", "--url", "http://example.com/mcp", "--timeout", "0"],
    )

    assert result.exit_code == 1
    assert "--timeout must be greater than 0" in result.output


def test_survey_reports_timeout_error(monkeypatch):
    async def fake_run_survey(**kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(cli, "run_survey", fake_run_survey)

    result = CliRunner().invoke(
        cli.app,
        ["survey", "--url", "http://example.com/mcp", "--timeout", "2"],
    )

    assert result.exit_code == 1
    assert "Request timed out after 2s" in result.output


@pytest.mark.asyncio
async def test_connect_http_uses_configured_timeout(monkeypatch):
    captured = {}

    @asynccontextmanager
    async def fake_streamable_http_client(url, *, http_client, terminate_on_close=True):
        captured["url"] = url
        captured["timeout"] = http_client.timeout.connect
        yield object(), object(), lambda: None

    class FakeClientSession:
        def __init__(self, read, write):
            self.read = read
            self.write = write

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def initialize(self):
            captured["initialized"] = True

    monkeypatch.setattr(mcp_connect, "streamable_http_client", fake_streamable_http_client)
    monkeypatch.setattr(mcp_connect, "ClientSession", FakeClientSession)

    async with mcp_connect.connect_http("http://example.com/mcp", timeout=12.5):
        pass

    assert captured == {
        "url": "http://example.com/mcp",
        "timeout": 12.5,
        "initialized": True,
    }
