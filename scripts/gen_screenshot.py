"""Generate a terminal SVG screenshot of mcpwn demo output."""
import asyncio
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style


def generate_svg(output_path: Path):
    console = Console(record=True, width=88, height=30, force_terminal=True, color_system="truecolor")

    console.print(Panel(
        "[bold cyan]MCPwn Security Survey[/]\n[dim]Target:[/] http://localhost:8080/mcp",
        title="MCPwn",
        border_style="cyan",
    ))

    console.print("\n[bold]Phase 1:[/] Enumerating tools...")
    console.print("  Found [green]7[/] tool(s)")
    tools = [
        ("execute_command", "Execute a system command"),
        ("read_file", "Read any file from the server"),
        ("search_database", "Query the internal database"),
        ("system_update", "Update system packages"),
        ("delete_logs", "Delete old log files"),
        ("fetch_url", "Fetch external URLs"),
        ("delayed_operation", "Process data through pipeline"),
    ]
    for name, desc in tools:
        console.print(f"    [dim]\u2022[/] {name}: {desc}")

    console.print("\n[bold]Phase 2:[/] Passive analysis (tool poisoning)...")
    console.print("  [yellow]Found 5 passive findings[/]")

    console.print("\n[bold]Phase 3:[/] Active injection testing...")
    console.print("  [red]![/] execute_command: 5 command injection vector(s)")
    console.print("  [red]![/] system_update: 5 command injection vector(s)")
    console.print("  [red]![/] fetch_url: 4 SSRF vector(s)")
    console.print("  [red]![/] delayed_operation: 1 blind RCE vector(s)")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", width=9)
    table.add_column("Count", width=6)
    table.add_row("[red]Critical[/]", "15")
    table.add_row("[yellow]High[/]", "3")
    table.add_row("[blue]Medium[/]", "4")
    table.add_row("[green]Low[/]", "1")

    console.print("\n[bold]Summary:[/] 23 total finding(s)")
    console.print(table)

    console.save_svg(str(output_path), title="mcpwn survey --url http://localhost:8080/mcp")


if __name__ == "__main__":
    generate_svg(Path(__file__).parent.parent / "docs" / "demo.svg")