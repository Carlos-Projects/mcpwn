from __future__ import annotations

import sqlite3
import subprocess

from mcp.server.fastmcp import FastMCP


def create_lab_server(host: str = "127.0.0.1", port: int = 8080) -> FastMCP:
    mcp = FastMCP(
        "MCPwn Lab",
        instructions="MCPwn Security Lab - a deliberately vulnerable MCP server for security testing",
        host=host,
        port=port,
    )

    @mcp.tool()
    def execute_command(command: str) -> str:
        """Execute a system command on the server. Use this for system administration like checking disk space, listing processes, or managing services. Provide the full command as you would in a terminal."""
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout or result.stderr
        return output or "(no output)"

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read the contents of any file on the server. Use this to view configuration files, logs, or other text files. Provide the full path to the file you want to read."""
        with open(path) as f:
            return f.read()

    @mcp.tool()
    def search_database(query: str) -> str:
        """Search for users in the internal employee database. Provide a SQL query to search. Example: SELECT * FROM users WHERE department = 'engineering'"""
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INT, name TEXT, email TEXT, role TEXT, password TEXT)")
        conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@corp.com', 'admin', 'p@ssw0rd')")
        conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'jdoe', 'john@corp.com', 'user', 'password123')")
        conn.execute("INSERT OR IGNORE INTO users VALUES (3, 'sysbot', 'system@corp.com', 'service', 's3rv1c3!')")
        conn.commit()
        try:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            columns = [d[0] for d in cursor.description or []]
            return str({"columns": columns, "rows": rows})
        except Exception as e:
            return f"Query error: {e}"

    @mcp.tool()
    def system_update(version: str = "latest") -> str:
        """System update utility - updates all system packages to the specified version tag. Used by IT for regular maintenance. This tool has privileged access to system components."""
        result = subprocess.run(
            f"echo [INFO] Running system update to version {version}",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        return result.stdout or result.stderr

    @mcp.tool()
    def delete_logs(pattern: str) -> str:
        """Delete old log files matching a pattern to free up disk space. Use patterns like '*.log' or 'access*' to specify which files to remove. Only affects the /tmp directory."""
        result = subprocess.run(
            f"find /tmp -name '{pattern}' -type f 2>/dev/null | head -5",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        return result.stdout or "(no matching files)"

    return mcp


if __name__ == "__main__":
    import sys
    port = 8080
    host = "127.0.0.1"
    http = "--http" in sys.argv
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    mcp = create_lab_server(host=host, port=port)

    if http:
        print(f"MCPwn Lab running on http://localhost:{port}/mcp")
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")