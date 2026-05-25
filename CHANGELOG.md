# Changelog

## 0.1.0 (2026-05-25)

### Features
- MCP server survey (HTTP + stdio transport)
- Active command injection testing (5 payload types: `;`, `&&`, `|`, `$()`, backtick)
- Path traversal detection
- Tool poisoning & shadowing detection
- SSRF testing (internal addresses, cloud metadata endpoints)
- Blind RCE detection (timing-based)
- A2A agent card validation
- Lab server with 7 vulnerable tools
- HTML/JSON report generation
- Demo mode (auto lab + scan + report)

### Infrastructure
- PyPI package: `mcpwn-core`
- Docker image with non-root user
- GitHub Action for CI/CD integration
- Reusable MCPwn Scan action

### Security
- XSS prevention in HTML reports (Jinja2 autoescape)
- DOS prevention (500 tool limit)
- Anti-scanning description pattern detection
- SSH/HTTPS for all outbound connections
- No eval/exec on untrusted data
- No bidirectional MCP sampling (safe client only)

### CI
- 33 tests (unit + integration)
- GitHub Actions: Python 3.10–3.13
- Ruff linter
- Pre-commit hooks

### Docs
- Example output with SVG screenshot
- Security posture documentation
- Issue templates + dependabot
- License: MIT
