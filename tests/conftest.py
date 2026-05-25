from mcp.types import Tool, ToolAnnotations


def make_tool(name: str, description: str = "", properties: dict | None = None, annotations: ToolAnnotations | None = None) -> Tool:
    return Tool(
        name=name,
        description=description,
        inputSchema={
            "type": "object",
            "properties": properties or {},
        },
        annotations=annotations or ToolAnnotations(),
    )


def make_result(text: str, is_error: bool = False):
    from mcp.types import CallToolResult, TextContent
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        isError=is_error,
    )
