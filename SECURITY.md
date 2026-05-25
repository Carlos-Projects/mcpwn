# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x | ✅ |

## Reporting a Vulnerability

MCPwn is an offensive security tool designed to find vulnerabilities in MCP servers. The tool itself is not intended for production deployment.

If you discover a security vulnerability in MCPwn's own code (not in the targets it scans):

- **Do not** open a public GitHub issue
- **Do** email: carlos@aiagentobservatory.org
- **Do** expect acknowledgment within 48 hours

## Responsible Disclosure

We ask that you give us reasonable time to fix a vulnerability before disclosing it publicly. We will credit researchers who report valid vulnerabilities in our release notes.

## Scope

The following are **in scope**:
- Code execution vulnerabilities in mcpwn's attack modules
- Privilege escalation in the CLI tool
- Data leakage from report outputs

The following are **out of scope**:
- The lab server (`mcpwn/mcpwn/lab/server.py`) is intentionally vulnerable by design
- Vulnerabilities in third-party dependencies
- Social engineering of the maintainers