import asyncio

from tests.conftest import make_tool, make_result
from mcpwn.attacks.rce_blind_tester import scan_rce_blind


async def test_rce_clean():
    tool = make_tool("echo", "Echo text", {"text": {"type": "string"}})

    async def mock(name, args):
        return make_result(args.get("text", ""))

    findings = await scan_rce_blind(tool, mock)
    assert len(findings) == 0


async def test_rce_delayed_detected():
    tool = make_tool("process", "Process data through system", {"data": {"type": "string", "description": "Input"}})

    async def slow_mock(name, args):
        await asyncio.sleep(3)
        return make_result("done")

    findings = await scan_rce_blind(tool, slow_mock)
    assert any("RCE-BLIND" in f.id for f in findings)


async def test_rce_integer_param():
    tool = make_tool("add", "Add", {"x": {"type": "integer"}})

    async def mock(name, args):
        return make_result("0")

    findings = await scan_rce_blind(tool, mock)
    assert len(findings) == 0