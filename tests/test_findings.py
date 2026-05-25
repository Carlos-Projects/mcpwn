from mcpwn.core.findings import Finding, ScanResult


def test_finding_creation():
    f = Finding(
        id="TEST-001",
        title="Test finding",
        severity="high",
        attack_type="command_injection",
        target="test_tool",
        description="A test",
        detail="Detail",
        recommendation="Fix it",
    )
    assert f.id == "TEST-001"
    assert f.severity == "high"
    assert f.attack_type == "command_injection"


def test_finding_with_evidence():
    f = Finding(
        id="TEST-002",
        title="Test with evidence",
        severity="critical",
        attack_type="tool_poisoning",
        target="bad_tool",
        description="Evidence test",
        detail="Details",
        recommendation="Remove it",
        evidence={"payload": "; id", "result": "uid=0"},
    )
    assert f.evidence["payload"] == "; id"


def test_scan_result_empty():
    r = ScanResult(target="localhost")
    assert r.summary["total"] == 0
    assert r.summary["by_severity"] == {}


def test_scan_result_with_findings():
    r = ScanResult(target="localhost")
    r.findings.append(Finding(id="A", title="A", severity="critical", attack_type="x", target="t", description="d", detail="dd", recommendation="r"))
    r.findings.append(Finding(id="B", title="B", severity="high", attack_type="x", target="t", description="d", detail="dd", recommendation="r"))
    r.findings.append(Finding(id="C", title="C", severity="medium", attack_type="x", target="t", description="d", detail="dd", recommendation="r"))
    r.findings.append(Finding(id="D", title="D", severity="low", attack_type="x", target="t", description="d", detail="dd", recommendation="r"))
    s = r.summary
    assert s["total"] == 4
    assert s["by_severity"]["critical"] == 1
    assert s["by_severity"]["high"] == 1
    assert s["by_severity"]["medium"] == 1
    assert s["by_severity"]["low"] == 1


def test_scan_result_to_dict():
    r = ScanResult(target="localhost")
    r.findings.append(Finding(id="A", title="A", severity="info", attack_type="x", target="t", description="d", detail="dd", recommendation="r"))
    d = r.to_dict()
    assert d["target"] == "localhost"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["id"] == "A"
