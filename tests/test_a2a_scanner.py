import httpx
import pytest

from mcpwn.attacks.a2a_scanner import scan_a2a_agent
from mcpwn.core.findings import Finding


def make_card(overrides: dict | None = None) -> dict:
    card = {
        "name": "TestAgent",
        "description": "A test agent",
        "url": "https://test-agent.example.com",
        "capabilities": {"streaming": True},
        "authentication": {"schemes": [{"type": "apiKey", "in": "header", "name": "X-API-Key"}]},
        "skills": [
            {"name": "search", "description": "Search documents"},
            {"name": "summarize", "description": "Summarize content"},
        ],
    }
    if overrides:
        card.update(overrides)
    return card


class MockTransport(httpx.MockTransport):
    def __init__(self, handler):
        super().__init__(handler)


def mock_client(json_response: dict | None = None, status: int = 200, text: str | None = None):
    async def handler(request):
        if text is not None:
            return httpx.Response(status, text=text)
        return httpx.Response(status, json=json_response or {})
    transport = MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


@pytest.mark.asyncio
async def test_valid_agent_card():
    client = mock_client(make_card())
    findings = await scan_a2a_agent("https://valid.example.com", client=client)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_missing_required_fields():
    client = mock_client({"url": "https://no-name.example.com"})
    findings = await scan_a2a_agent("https://no-name.example.com", client=client)
    ids = {f.id for f in findings}
    assert "A2A-MISSING-NAME" in ids
    assert "A2A-MISSING-DESCRIPTION" in ids
    assert "A2A-MISSING-URL" not in ids  # url is present


@pytest.mark.asyncio
async def test_suspicious_skill_name():
    card = make_card({"skills": [{"name": "exec_command", "description": "Execute"}]})
    client = mock_client(card)
    findings = await scan_a2a_agent("https://suspicious.example.com", client=client)
    sus = [f for f in findings if "SUS" in f.id]
    assert len(sus) >= 1


@pytest.mark.asyncio
async def test_no_auth():
    card = make_card({"authentication": {"schemes": []}})
    client = mock_client(card)
    findings = await scan_a2a_agent("https://no-auth.example.com", client=client)
    assert any("A2A-NO-AUTH" in f.id for f in findings)


@pytest.mark.asyncio
async def test_no_skills():
    card = make_card({"skills": []})
    client = mock_client(card)
    findings = await scan_a2a_agent("https://no-skills.example.com", client=client)
    assert any("A2A-NO-SKILLS" in f.id for f in findings)


@pytest.mark.asyncio
async def test_duplicate_skill_name():
    card = make_card({"skills": [{"name": "search"}, {"name": "search"}]})
    client = mock_client(card)
    findings = await scan_a2a_agent("https://dup.example.com", client=client)
    assert any("A2A-SKILL-DUP" in f.id for f in findings)


@pytest.mark.asyncio
async def test_http_error():
    client = mock_client(status=404)
    findings = await scan_a2a_agent("https://404.example.com", client=client)
    assert any("A2A-FETCH-HTTP" in f.id for f in findings)


@pytest.mark.asyncio
async def test_invalid_json():
    client = mock_client(text="not json")
    findings = await scan_a2a_agent("https://bad-json.example.com", client=client)
    assert any("A2A-FETCH-JSON" in f.id for f in findings)
