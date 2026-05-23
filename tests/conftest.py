from mcp.types import Tool, ToolAnnotations


def make_tool(name: str, description: str = "", properties: dict | None = None) -> Tool:
    return Tool(
        name=name,
        description=description,
        inputSchema={
            "type": "object",
            "properties": properties or {},
        },
        annotations=ToolAnnotations(),
    )
