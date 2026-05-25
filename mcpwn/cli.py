from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from mcpwn.attacks.a2a_scanner import scan_a2a_agent
from mcpwn.attacks.injection_tester import (
    test_command_injection,
    test_path_traversal,
)
from mcpwn.attacks.rce_blind_tester import scan_rce_blind
from mcpwn.attacks.ssrf_tester import scan_ssrf
from mcpwn.attacks.tool_analysis import analyze_tools
from mcpwn.core.findings import ScanResult
from mcpwn.core.report import generate_html_report, save_json
from mcpwn.utils.mcp_connect import connect_stdio

console = Console()
app = typer.Typer(name="mcpwn", help="Offensive security testing framework for MCP protocols")

SEVERITY_COLORS = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}


def print_results(scan_result: ScanResult, output: Path | None, html: Path | None):
    summary = scan_result.summary
    console.print(f"\n[bold]Summary:[/] {summary['total']} total finding(s)")
    for sev in ["critical", "high", "medium", "low"]:
        count = summary["by_severity"].get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "white")
            console.print(f"  [{color}]{sev}: {count}[/]")

    result_dict = scan_result.to_dict()

    if output:
        save_json(result_dict, output)
        console.print(f"\nResults saved to [green]{output}[/]")

    if html:
        generate_html_report(result_dict, html)
        console.print(f"HTML report saved to [green]{html}[/]")

    if not output and not html:
        print(json.dumps(result_dict, indent=2))


async def run_survey(
    url: str | None = None,
    stdio: str | None = None,
    no_injection: bool = False,
) -> ScanResult:
    target = stdio or url or "unknown"

    if url:
        from mcpwn.utils.mcp_connect import connect_http
        ctx = connect_http(url)
    else:
        parts = stdio.split()
        ctx = connect_stdio(parts[0], parts[1:] if len(parts) > 1 else None)

    async with ctx as session:
        result = ScanResult(target=target)

        console.print("\n[bold]Phase 1:[/] Enumerating tools...")
        tools_result = await session.list_tools()
        tools = tools_result.tools
        console.print(f"  Found [green]{len(tools)}[/] tool(s)")

        if not tools:
            console.print("[yellow]  No tools to analyze.[/]")
            return result

        for t in tools:
            console.print(f"    [dim]\u2022[/] {t.name}: {t.description or '(no description)'}")

        console.print("\n[bold]Phase 2:[/] Passive analysis (tool poisoning detection)...")
        findings = analyze_tools(tools)
        result.findings.extend(findings)
        console.print(f"  Found [yellow]{len(findings)}[/] passive findings")

        if not no_injection:
            console.print("\n[bold]Phase 3:[/] Active injection testing...")

            async def call_tool(name, arguments):
                return await session.call_tool(name, arguments)

            for tool in tools:
                cmd_findings = await test_command_injection(tool, call_tool)
                result.findings.extend(cmd_findings)
                if cmd_findings:
                    console.print(f"  [red]![/] {tool.name}: {len(cmd_findings)} command injection vector(s)")

                path_findings = await test_path_traversal(tool, call_tool)
                result.findings.extend(path_findings)
                if path_findings:
                    console.print(f"  [red]![/] {tool.name}: {len(path_findings)} path traversal vector(s)")

                ssrf_findings = await scan_ssrf(tool, call_tool)
                result.findings.extend(ssrf_findings)
                if ssrf_findings:
                    console.print(f"  [red]![/] {tool.name}: {len(ssrf_findings)} SSRF vector(s)")

                rce_findings = await scan_rce_blind(tool, call_tool)
                result.findings.extend(rce_findings)
                if rce_findings:
                    console.print(f"  [red]![/] {tool.name}: {len(rce_findings)} blind RCE vector(s)")

            total_active = len(result.findings) - len(findings)
            console.print(f"  Found [red]{total_active}[/] active findings")

        return result


@app.command()
def survey(
    stdio: str = typer.Option(None, "--stdio", help="Command to start the MCP server (e.g. 'uv run server.py')"),
    url: str = typer.Option(None, "--url", help="MCP server URL (e.g. http://localhost:8080/mcp)"),
    output: Path = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    html: Path = typer.Option(None, "--html", help="Generate HTML report"),
    no_injection: bool = typer.Option(False, "--no-injection", help="Skip active injection tests"),
):
    """Survey an MCP server for security vulnerabilities."""
    if not stdio and not url:
        console.print("[red]Error: Provide either --stdio or --url[/]")
        raise typer.Exit(1)

    target = stdio or url
    console.print(Panel(f"[bold cyan]MCPwn Security Survey[/]\n[dim]Target:[/] {target}", title="MCPwn"))

    try:
        scan_result = asyncio.run(run_survey(url=url, stdio=stdio, no_injection=no_injection))
    except ConnectionRefusedError:
        console.print("[red]Error: Connection refused.[/] Is the server running and accessible?")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)

    print_results(scan_result, output, html)


@app.command()
def demo(
    port: int = typer.Option(8080, "--port", "-p", help="Port for lab server"),
):
    """Run a complete demo: start lab, scan it, show findings, clean up."""
    console.print(Panel("[bold cyan]MCPwn Demo[/]\nStarting lab server \u2192 Scanning \u2192 Reporting", title="MCPwn"))

    proc = subprocess.Popen(
        [sys.executable, "-m", "mcpwn.lab.server", "--http", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    try:
        import httpx
        for _ in range(15):
            time.sleep(1)
            try:
                httpx.get(f"http://127.0.0.1:{port}/mcp", timeout=2)
                break
            except Exception:
                continue
        else:
            console.print("[red]Failed to start lab server[/]")
            proc.kill()
            raise typer.Exit(1)

        url = f"http://127.0.0.1:{port}/mcp"
        scan_result = asyncio.run(run_survey(url=url, no_injection=False))

        tmp_path = Path(tempfile.mkdtemp()) / "results.json"
        save_json(scan_result.to_dict(), tmp_path)

        summary = scan_result.summary
        console.print(f"\n[bold]Demo complete:[/] {summary['total']} findings detected")
        for sev, count in sorted(summary["by_severity"].items()):
            color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(sev, "white")
            console.print(f"  [{color}]{sev}: {count}[/]")

        tmp_path.unlink(missing_ok=True)
        tmp_path.parent.rmdir()
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except ProcessLookupError:
            pass
        except Exception:
            proc.kill()
        try:
            tmp_path.unlink(missing_ok=True)
            tmp_path.parent.rmdir()
        except Exception:
            pass
        console.print("[dim]Lab stopped, cleaned up.[/]")


@app.command()
def lab(
    http: bool = typer.Option(False, "--http", help="Run as HTTP server instead of stdio"),
    port: int = typer.Option(8080, "--port", "-p", help="Port for HTTP server"),
):
    """Start the MCPwn vulnerable lab server for practice."""
    if http:
        console.print(f"[bold green]MCPwn Lab[/] running on [underline]http://localhost:{port}/mcp[/]")
        console.print(f"In another terminal: [bold]mcpwn survey --url http://localhost:{port}/mcp[/]\n")
    else:
        console.print("[bold green]MCPwn Lab[/] starting on stdio...")
        console.print(f"  [bold]mcpwn survey --stdio \"{sys.executable} -m mcpwn.lab.server\"[/]\n")

    cmd = [sys.executable, "-m", "mcpwn.lab.server"]
    if http:
        cmd.extend(["--http", "--port", str(port)])
    proc = subprocess.run(cmd)
    return proc.returncode


@app.command()
def report(
    input_file: Path = typer.Argument(..., help="JSON results file"),
    output: Path = typer.Option("report.html", "--output", "-o", help="Output HTML file"),
):
    """Generate an HTML report from a JSON results file."""
    if not input_file.exists():
        console.print(f"[red]Error: File not found: {input_file}[/]")
        raise typer.Exit(1)
    try:
        data = json.loads(input_file.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON in {input_file}: {e}[/]")
        raise typer.Exit(1)
    path = generate_html_report(data, output)
    console.print(f"Report generated: [green]{path}[/]")


@app.command(name="survey-a2a")
def survey_a2a(
    url: str = typer.Argument(..., help="A2A agent URL (e.g. https://agent.example.com)"),
    output: Path = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
    html: Path = typer.Option(None, "--html", help="Generate HTML report"),
):
    """Survey an A2A agent by fetching and validating its agent card."""
    console.print(Panel(f"[bold cyan]MCPwn A2A Survey[/]\n[dim]Target:[/] {url}", title="MCPwn"))

    try:
        async def run():
            result = ScanResult(target=url)
            console.print("\n[bold]Phase 1:[/] Fetching agent card...")
            findings = await scan_a2a_agent(url)
            result.findings.extend(findings)
            console.print(f"  Found [yellow]{len(findings)}[/] finding(s)")
            return result

        scan_result = asyncio.run(run())
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)

    print_results(scan_result, output, html)


if __name__ == "__main__":
    app()
