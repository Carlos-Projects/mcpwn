# MCPwn

Offensive security testing framework for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers.

Unlike passive scanners (Cisco MCP Scanner, mcp-scan), **MCPwn actively tests** MCP servers by sending real attack payloads and analyzing responses. It includes a deliberately vulnerable lab server for practice.

## Installation

```bash
pip install -e .
```

## Usage

### Survey an MCP server

```bash
# Via HTTP (Streamable HTTP transport)
mcpwn survey --url http://localhost:8080/mcp

# Via stdio (local process)
mcpwn survey --stdio "uv run my_server.py"

# Save results
mcpwn survey --url http://localhost:8080/mcp --output results.json --html report.html
```

### Start the vulnerable lab

```bash
# HTTP mode (recommended)
mcpwn lab --http --port 8080

# Then in another terminal:
mcpwn survey --url http://localhost:8080/mcp
```

### Generate HTML reports

```bash
mcpwn report results.json --output report.html
```

## Attack modules

### Passive analysis (always runs)

- **Tool poisoning detection**: Flags dangerous tool names (`exec`, `eval`, `shell`, `delete`, `system`, etc.)
- **Tool shadowing**: Detects tools with the same names as common MCP tools
- **Suspicious descriptions**: Finds instruction-like content in tool descriptions

### Active injection testing (requires tool calls)

- **Command injection**: Tests 5 payload types (`;`, `&&`, `|`, `$()`, backtick) against each string parameter
- **Path traversal**: Tests `../../../etc/passwd` patterns on file-related parameters

## Security warnings

> **⚠️ The lab server is intentionally vulnerable.** Never deploy it to production, expose it to a network other than localhost, or run it on a machine with sensitive data. It contains deliberate command injection, SQL injection, and path traversal vulnerabilities for educational purposes.

> **⚠️ The `--stdio` flag spawns a process from user input.** Only use it to connect to MCP servers you own or trust.

## Lab server

The lab (`mcpwn lab`) starts a deliberately vulnerable MCP server for security testing. It contains 5 intentionally vulnerable tools:

| Tool | Vulnerability | Description |
|---|---|---|
| `execute_command` | Command injection | `subprocess.run(cmd, shell=True)` |
| `read_file` | Path traversal | `open(path).read()` without sanitization |
| `search_database` | SQL injection | Direct query interpolation |
| `system_update` | Command injection | Shell interpolation of version param |
| `delete_logs` | Argument injection | Shell interpolation of pattern param |

## Architecture

```
mcpwn/
├── mcpwn/
│   ├── cli.py              # Typer CLI (survey, lab, report)
│   ├── core/
│   │   ├── findings.py     # Finding, ScanResult models
│   │   └── report.py       # HTML report generator
│   ├── attacks/
│   │   ├── tool_analysis.py    # Passive tool scrutiny
│   │   └── injection_tester.py # Active injection tests
│   ├── lab/
│   │   └── server.py       # Vulnerable MCP server
│   └── utils/
│       └── mcp_connect.py  # MCP connection helpers
└── pyproject.toml
```

## Why not just use Cisco MCP Scanner?

| Tool | Approach | MCPwn difference |
|---|---|---|
| Cisco MCP Scanner | Static YARA + LLM analysis | MCPwn **calls tools** with attack payloads |
| mcp-scan | Config/tool metadata checks | MCPwn **confirms** vulnerabilities via execution |
| MCPwn | Active red team testing | Includes **lab**, **path traversal**, **reporting** |

## Requirements

- Python 3.10+
- `mcp`, `typer`, `rich`, `httpx`, `jinja2`