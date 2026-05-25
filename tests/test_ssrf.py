from tests.conftest import make_tool, make_result
from mcpwn.attacks.ssrf_tester import scan_ssrf


async def test_ssrf_clean():
    tool = make_tool("add", "Add numbers", {"a": {"type": "integer"}})

    async def mock(name, args):
        return make_result("42")

    findings = await scan_ssrf(tool, mock)
    assert len(findings) == 0


async def test_ssrf_url_param_detected():
    tool = make_tool("fetch", "Fetch a URL", {"url": {"type": "string", "description": "URL to fetch"}})

    async def mock(name, args):
        return make_result("Error: Connection refused")

    findings = await scan_ssrf(tool, mock)
    assert any(f.attack_type == "ssrf" for f in findings)


async def test_ssrf_no_url_param():
    tool = make_tool("run", "Run something", {"cmd": {"type": "string"}})

    async def mock(name, args):
        return make_result("ok")

    findings = await scan_ssrf(tool, mock)
    assert len(findings) == 0


async def test_ssrf_non_url_param():
    tool = make_tool("fetch", "Fetch something", {"target": {"type": "string", "description": "Target to fetch"}})

    async def mock(name, args):
        return make_result("Error: Connection timed out")

    findings = await scan_ssrf(tool, mock)
    assert len(findings) == 6