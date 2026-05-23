# Contributing to MCPwn

## Getting Started

```bash
git clone https://github.com/yourusername/mcpwn
cd mcpwn
pip install -e ".[dev]"
```

## Development Guidelines

### Code style
- No docstrings or comments unless necessary (code should be self-documenting)
- Use `from __future__ import annotations` in all files
- Type hints for all function signatures
- Follow existing patterns in the codebase

### Adding a new attack module
1. Create `mcpwn/attacks/your_attack.py`
2. Define an async function that takes `tool: Tool` and `call_tool_fn`
3. Return a `list[Finding]`
4. Wire it up in `mcpwn/cli.py`'s survey command

### Adding a new lab vulnerability
1. Add a new tool to `mcpwn/lab/server.py`
2. Make sure it's documented in the README table
3. Verify it's detected by an attack module

### Testing
```bash
pip install -e ".[dev]"
pytest -v
```

### Pull Request Checklist
- [ ] Tests pass (`pytest -v`)
- [ ] No new `shell=True` outside lab server
- [ ] License headers not required

## License
By contributing you agree that your contributions will be licensed under the MIT License.