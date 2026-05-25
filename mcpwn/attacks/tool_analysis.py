from __future__ import annotations

import re

from mcp.types import Tool

from mcpwn.core.findings import Finding, Severity

SUSPICIOUS_NAMES = {
    "exec": "Execute arbitrary commands on the server",
    "execute": "Execute arbitrary commands on the server",
    "shell": "Execute arbitrary commands via shell",
    "run": "Execute arbitrary commands or scripts",
    "system": "Execute system-level commands",
    "eval": "Evaluate arbitrary code",
    "delete": "Destructive file/data operation",
    "drop": "Destructive database operation",
    "remove": "Destructive file operation",
    "rm": "Destructive file operation",
    "shutdown": "System shutdown or service termination",
    "format": "Destructive data destruction operation",
    "wipe": "Destructive data destruction operation",
    "destroy": "Destructive resource termination",
    "purge": "Destructive data removal",
    "truncate": "Destructive table/data operation",
    "mkfs": "Filesystem creation (potentially destructive)",
    "dd": "Raw disk operation (potentially destructive)",
    "reboot": "System restart operation",
}

SUSPICIOUS_DESCRIPTION_PATTERNS = [
    (r"ignore\s+(previous|all|prior)\s+(instructions|commands)", "Contains instruction override keywords"),
    (r"always\s+(return|say|respond|answer)", "Potentially manipulates LLM behavior"),
    (r"never\s+(follow|obey|listen)", "Contains refusal-to-comply language"),
    (r"do\s+not\s+(follow|obey|listen|check)", "Contains override instructions"),
    (r"override", "Contains override instructions"),
    (r"trust\s+me", "Social engineering indicator in description"),
    (r"(the\s+)?user\s+is\s+(always|admin|root|god)", "Claims of special user status"),
    (r"skip\s+(validation|check|verification|auth)", "Bypass security controls"),
    (r"bypass\s+(security|validation|auth|check)", "Bypass security controls"),
    # Anti-scanning / anti-analysis patterns
    (r"(this\s+)?tool\s+is\s+(safe|benign|harmless)", "Self-proclaimed safe tool (social engineering)"),
    (r"(is\s+)?not\s+(malicious|dangerous|harmful)", "Claims of non-malicious intent"),
    (r"do\s+not\s+(scan|analyze|audit|inspect)", "Instructions to avoid security analysis"),
    (r"skip\s+(me|this|scanning)", "Attempt to bypass scanning"),
    (r"false\s+(positive|alarm)", "Dismisses potential findings in advance"),
    (r"(this|the)\s+is\s+(a\s+)?(legitimate|required|necessary)\s+(tool|command|operation)", "Claims of legitimacy to avoid scrutiny"),
]

COMMON_MCP_TOOLS = {
    "read_file", "write_file", "edit_file", "create_file",
    "search_web", "fetch_url", "http_request",
    "list_directory", "get_weather", "calculate",
    "send_email", "query_database", "run_sql",
}


def _severity_from_name(name: str) -> Severity:
    high_risk = {"exec", "execute", "shell", "eval", "shutdown", "format", "wipe", "destroy", "purge", "dd", "mkfs", "reboot"}
    if name.lower() in high_risk:
        return "high"
    return "medium"


def analyze_tools(tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    seen_names: set[str] = set()

    for tool in tools:
        name_lower = tool.name.lower()

        for suspicious_name, reason in sorted(SUSPICIOUS_NAMES.items(), key=lambda x: -len(x[0])):
            if suspicious_name in name_lower:
                findings.append(Finding(
                    id=f"TOOL-SUS-NAME-{suspicious_name}",
                    title=f"Suspicious tool name: '{tool.name}' contains '{suspicious_name}'",
                    severity=_severity_from_name(suspicious_name),
                    attack_type="tool_poisoning",
                    target=tool.name,
                    description=f"Tool name '{tool.name}' contains '{suspicious_name}' which suggests {reason.lower()}.",
                    detail=f"Full name: {tool.name}\nDescription: {tool.description or '(none)'}\nInput schema: {tool.inputSchema}",
                    recommendation="Review this tool's implementation. If it performs the operation suggested by its name, restrict access or remove it. Rename to avoid ambiguity.",
                    evidence={"name": tool.name, "suspicious_part": suspicious_name, "reason": reason},
                ))
                break

        if tool.description:
            for pattern, reason in SUSPICIOUS_DESCRIPTION_PATTERNS:
                if re.search(pattern, tool.description, re.IGNORECASE):
                    findings.append(Finding(
                        id=f"TOOL-SUS-DESC-{len(findings)}",
                        title=f"Suspicious description pattern in '{tool.name}'",
                        severity="high",
                        attack_type="tool_poisoning",
                        target=tool.name,
                        description=f"Tool description contains suspicious pattern: {reason}.",
                        detail=f"Tool: {tool.name}\nDescription: {tool.description}",
                        recommendation="Review the tool description. Descriptions are passed to LLMs and can manipulate model behavior. Remove any instruction-like content.",
                        evidence={"name": tool.name, "description": tool.description, "pattern": pattern},
                    ))
                    break

        if tool.name in COMMON_MCP_TOOLS:
            findings.append(Finding(
                id=f"TOOL-SHADOW-{tool.name}",
                title=f"Tool name '{tool.name}' shadows a common MCP tool",
                severity="medium",
                attack_type="tool_poisoning",
                target=tool.name,
                description=f"Tool name '{tool.name}' matches a well-known MCP tool. This could be a shadowing attack.",
                detail=f"This server exposes a tool named '{tool.name}' which matches a common tool name. In multi-server setups, a malicious server could intercept calls intended for a legitimate one.",
                recommendation="If this server is not the legitimate source of this tool, remove or rename it to prevent shadowing.",
                evidence={"name": tool.name, "shadowed_tool": True},
            ))

        seen_names.add(tool.name)

    return findings
