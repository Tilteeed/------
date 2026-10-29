"""Framework-independent policies; no Docker access and no network calls."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AgentSettings:
    name: str
    instructions: str = ""


def validate_agent_input(payload: object) -> AgentSettings:
    """Validate browser settings; infrastructure and owner fields are forbidden.

    Lengths are application input bounds, not a prompt-injection detector.
    Instructions remain untrusted text and must be escaped when rendered.
    """
    if not isinstance(payload, dict):
        raise ValueError("Settings must be an object")
    allowed = {"name", "instructions"}
    if set(payload) - allowed:
        raise ValueError("Only name and instructions may be supplied")
    name = payload.get("name")
    instructions = payload.get("instructions", "")
    if not isinstance(name, str):
        raise ValueError("Name must be text")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Name must not contain control characters")
    name = name.strip()
    if not 1 <= len(name) <= 80:
        raise ValueError("Name must contain between 1 and 80 characters")
    if not isinstance(instructions, str) or len(instructions) > 8000:
        raise ValueError("Instructions must be text up to 8000 characters")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in instructions):
        raise ValueError("Instructions contain unsupported control characters")
    return AgentSettings(name=name, instructions=instructions)


def require_owner(actor_id: object, owner_id: object) -> None:
    """Fail closed unless a verified server identity owns the requested object.

    The caller MUST obtain actor_id from authenticated server context, and
    owner_id from storage. This helper neither authenticates an identity nor
    accepts a browser's claim to be an administrator.
    """
    valid = all(
        isinstance(value, str) and bool(value) and value == value.strip()
        for value in (actor_id, owner_id)
    )
    if not valid or actor_id != owner_id:
        raise PermissionError("Instance access denied")
