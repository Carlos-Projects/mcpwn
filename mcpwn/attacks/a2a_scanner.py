from __future__ import annotations

from mcpwn.core.findings import Finding


SUSPICIOUS_SKILL_NAMES = {
    "exec", "execute", "shell", "eval", "delete", "drop", "remove", "rm",
    "shutdown", "format", "wipe", "destroy", "purge", "dd", "mkfs", "reboot",
}

REQUIRED_CARD_FIELDS = {"name", "description", "url"}


async def scan_a2a_agent(url: str, client=None) -> list[Finding]:
    findings: list[Finding] = []
    import httpx

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=15)
        close_client = True

    try:
        base = url.rstrip("/")
        card_url = base + "/.well-known/agent-card.json"

        try:
            resp = await client.get(card_url)
            resp.raise_for_status()
            card = resp.json()
        except httpx.HTTPStatusError as e:
            findings.append(Finding(
                id="A2A-FETCH-HTTP",
                title=f"Agent card fetch failed: HTTP {e.response.status_code}",
                severity="high",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description=f"Could not fetch agent card from {card_url}",
                detail=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
                recommendation="Ensure agent card is accessible at the standard path",
                evidence={"url": card_url, "status": e.response.status_code},
            ))
            return findings
        except httpx.RequestError as e:
            findings.append(Finding(
                id="A2A-FETCH-NET",
                title="Agent card fetch failed: network error",
                severity="high",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description=f"Could not connect to fetch agent card: {e}",
                detail=str(e),
                recommendation="Verify the agent URL is correct and the server is reachable",
                evidence={"url": card_url, "error": str(e)},
            ))
            return findings
        except ValueError:
            findings.append(Finding(
                id="A2A-FETCH-JSON",
                title="Agent card is not valid JSON",
                severity="high",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description="The agent card response is not valid JSON",
                detail="The response body could not be parsed as JSON",
                recommendation="Ensure the agent card is valid JSON",
                evidence={"url": card_url},
            ))
            return findings

        if not isinstance(card, dict):
            findings.append(Finding(
                id="A2A-NOT-DICT",
                title="Agent card is not a JSON object",
                severity="high",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description="The agent card must be a JSON object at the top level",
                detail=f"Got type: {type(card).__name__}",
                recommendation="Ensure the agent card is a JSON object",
                evidence={"url": card_url},
            ))
            return findings

        for field in REQUIRED_CARD_FIELDS:
            if field not in card or not card[field]:
                findings.append(Finding(
                    id=f"A2A-MISSING-{field.upper()}",
                    title=f"Agent card missing required field: '{field}'",
                    severity="high",
                    attack_type="a2a_misconfiguration",
                    target=card_url,
                    description=f"Required field '{field}' is missing or empty in the agent card",
                    detail=f"Fields present: {list(card.keys())}",
                    recommendation="Add the required field to the agent card per the A2A spec",
                    evidence={"url": card_url, "missing_field": field},
                ))

        skills = card.get("skills", [])
        if not skills:
            findings.append(Finding(
                id="A2A-NO-SKILLS",
                title="Agent card declares no skills",
                severity="low",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description="The agent card has no skills. Agents should declare at least one skill.",
                detail="Skills array is empty or missing",
                recommendation="Add skills to the agent card",
                evidence={"url": card_url},
            ))

        seen_skill_names: set[str] = set()
        for skill in skills:
            skill_name = skill.get("name", "(unnamed)")

            if skill_name in seen_skill_names:
                findings.append(Finding(
                    id="A2A-SKILL-DUP",
                    title=f"Duplicate skill name: '{skill_name}'",
                    severity="medium",
                    attack_type="a2a_misconfiguration",
                    target=f"{card_url}/skills/{skill_name}",
                    description=f"Multiple skills share the name '{skill_name}'",
                    detail=f"Skill name '{skill_name}' appears more than once",
                    recommendation="Rename skills to have unique names",
                    evidence={"url": card_url, "skill": skill_name},
                ))
            seen_skill_names.add(skill_name)

            name_lower = skill_name.lower()
            for suspicious in SUSPICIOUS_SKILL_NAMES:
                if suspicious in name_lower:
                    findings.append(Finding(
                        id=f"A2A-SKILL-SUS-{suspicious}",
                        title=f"Suspicious skill name: '{skill_name}' contains '{suspicious}'",
                        severity="medium",
                        attack_type="a2a_tool_poisoning",
                        target=f"{card_url}/skills/{skill_name}",
                        description=f"Skill name '{skill_name}' contains '{suspicious}'",
                        detail="Suspicious pattern found in skill name",
                        recommendation="Review this skill for potentially dangerous behavior",
                        evidence={"url": card_url, "skill": skill_name, "suspicious_part": suspicious},
                    ))
                    break

        auth = card.get("authentication", {})
        schemes = auth.get("schemes", [])
        if not schemes:
            findings.append(Finding(
                id="A2A-NO-AUTH",
                title="Agent card has no authentication scheme",
                severity="high",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description="No authentication schemes defined. The agent is accessible without authentication.",
                detail=f"Authentication field: {auth}",
                recommendation="Add at least one authentication scheme (API key, OAuth, etc.)",
                evidence={"url": card_url},
            ))

        caps = card.get("capabilities", {})
        streaming = caps.get("streaming", False)
        if not streaming:
            findings.append(Finding(
                id="A2A-NO-STREAM",
                title="Agent does not support streaming",
                severity="info",
                attack_type="a2a_misconfiguration",
                target=card_url,
                description="Agent card does not advertise streaming support",
                detail="Streaming is recommended for real-time agent communication",
                recommendation="Consider enabling streaming for better UX",
                evidence={"url": card_url},
            ))

        return findings

    finally:
        if close_client:
            await client.aclose()