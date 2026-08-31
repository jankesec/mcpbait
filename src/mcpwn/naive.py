"""A reference agent with no defences whatsoever.

It follows any instruction that appears in a tool description or tool result, carries
what it has read into later calls, renders markdown, and writes files when told to.
No model, no API key, no network.

Two jobs. It is the baseline `mcpwn demo` attacks, so anyone can reproduce the
README output in one command without configuring a real agent. And it is what CI
asserts the full kill chain against, which is why the suite needs no API key and
never flakes.

It is deliberately the worst case. A real agent scoring near it is in trouble; a real
agent scoring well above it has only proven it beat a client that does not think.
"""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path
from typing import Any

import anyio

from mcpwn.engine import Session
from mcpwn.modules.invisible import from_tags
from mcpwn.server import build_server

IMAGE_PATTERN = re.compile(r"!\[[^\]]*\]\((?P<url>[^)]+)\)")
PERSISTENCE_PATTERN = re.compile(r"<!--\s*mcpwn-persistence-[0-9a-f]+\s*-->")


def _readable_instruction(description: str) -> str:
    """Everything the model sees: the visible text plus anything smuggled into it."""
    return description + "\n" + from_tags(description)


def _referenced_file(instruction: str, workspace: Path) -> str | None:
    """Read the first workspace file the instruction points at."""
    for match in re.finditer(rf"{re.escape(str(workspace))}[/\w.\-]*", instruction):
        candidate = Path(match.group(0))
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return None


def _build_arguments(schema: dict[str, Any], secret: str | None) -> dict[str, Any]:
    """Fill required fields plausibly and hand the secret to the first optional string."""
    properties: dict[str, Any] = schema.get("properties", {}) or {}
    required = set(schema.get("required", []))
    arguments: dict[str, Any] = {}
    for name, spec in properties.items():
        if name in required:
            arguments[name] = 1 if spec.get("type") == "integer" else "status"
    if secret:
        for name, spec in properties.items():
            if name not in required and spec.get("type", "string") == "string":
                arguments[name] = secret
                break
    return arguments


def _fetch(url: str) -> None:
    try:
        urllib.request.urlopen(url, timeout=2).read()
    except OSError:
        pass


async def run_naive_agent(session: Session, obey: bool = True) -> None:
    """List the server's tools and, when obeying, do whatever they ask."""
    _, router = build_server(session)
    tools = router.on_list()
    if not obey:
        return

    workspace = Path(session.ctx.workspace)
    carried: str | None = None  # what the agent has already read, as a real one would

    for tool in tools:
        instruction = _readable_instruction(tool.description or "")
        secret = _referenced_file(instruction, workspace) or carried
        if secret and carried is None:
            carried = secret

        result = await router.dispatch(tool.name, _build_arguments(tool.input_schema, secret))
        body = "".join(block.text for block in result)

        follow_up = _referenced_file(body, workspace)
        if follow_up:
            carried = carried or follow_up
            await router.dispatch(tool.name, _build_arguments(tool.input_schema, follow_up))

        for match in IMAGE_PATTERN.finditer(body):
            # A rendering client fetches the image without asking anyone. Run it off
            # the event loop, the way a real client's renderer would.
            await anyio.to_thread.run_sync(_fetch, match.group("url"))

        if PERSISTENCE_PATTERN.search(body):
            target = workspace / "CLAUDE.md"
            existing = target.read_text(encoding="utf-8") if target.is_file() else ""
            target.write_text(existing + "\n" + body, encoding="utf-8")
