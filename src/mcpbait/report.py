"""Kill chain reporting.

The terminal output is the artefact people screenshot and paste into issues, so it
carries two obligations: it must be readable without colour, and it must never claim
more than the evidence supports.

Redaction policy: the raw JSONL session log keeps everything, because that is the
operator's evidence. Anything rendered by this module is treated as shareable and
has canary values cut to a recognisable prefix. Synthetic secrets are still secrets
once they are in a screenshot on the internet.
"""

from __future__ import annotations

import html
import re
import time
from datetime import UTC, datetime
from typing import Any

from rich.console import Console
from rich.table import Table

from mcpbait.canary import MARKER
from mcpbait.engine import Session
from mcpbait.modules import REGISTRY
from mcpbait.types import Verdict

PROOF_KINDS = ("canary_hit", "beacon_hit", "persistence_confirmed")

#: Plain-text labels so a monochrome screenshot still reads correctly.
EVENT_LABELS = {
    "payload_delivered": "PAYLOAD SERVED",
    "payload_mutated": "RUG PULL",
    "tool_call": "TOOL CALLED",
    "canary_hit": "EXFIL CAUGHT",
    "beacon_hit": "BEACON HIT",
    "persistence_confirmed": "PERSISTED",
    "name_collision": "NAME COLLISION",
    "module_error": "MODULE ERROR",
}

VERDICT_STYLES = {
    Verdict.COMPROMISED: "bold red",
    Verdict.BAITED: "yellow",
    Verdict.IGNORED: "cyan",
    Verdict.BLOCKED: "green",
    Verdict.NOT_RUN: "dim",
}

#: Matches a canary even when the session was reloaded and the values are unknown.
_MARKER_TOKEN = re.compile(rf"\S*{MARKER}\S*")


def _shorten(value: str) -> str:
    return value[:8] + "..." if len(value) > 8 else value


def _redact(node: Any, canaries: dict[str, str]) -> Any:
    """Recursively cut every canary down to a recognisable prefix."""
    if isinstance(node, str):
        text = node
        for value in canaries.values():
            if value in text:
                text = text.replace(value, _shorten(value))
        return _MARKER_TOKEN.sub(lambda m: _shorten(m.group(0)), text)
    if isinstance(node, dict):
        return {key: _redact(value, canaries) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact(value, canaries) for value in node]
    return node


def _canaries(session: Session) -> dict[str, str]:
    return session.ctx.canaries if session.ctx else {}


def _metadata(module_id: str) -> tuple[str, str]:
    """Phase and ATLAS id for a module, resolved from the registry."""
    cls = REGISTRY.get(module_id)
    return (str(cls.phase), cls.atlas_id) if cls else ("-", "-")


def to_dict(session: Session) -> dict[str, Any]:
    """The shareable form of a session: redacted, JSON-serialisable, self-describing."""
    canaries = _canaries(session)
    verdicts = session.verdicts()
    evidence = [
        _redact(event.detail | {"module": event.module_id, "kind": event.kind}, canaries)
        for event in session.events
        if event.kind in PROOF_KINDS
    ]
    return {
        "session_id": session.id,
        "started": datetime.fromtimestamp(session.started, tz=UTC).astimezone().isoformat(timespec="seconds"),
        "score": session.score(),
        "verdicts": {module_id: str(verdict) for module_id, verdict in verdicts.items()},
        "evidence": evidence,
        "events": [
            {
                "ts": event.ts,
                "kind": event.kind,
                "module": event.module_id,
                "detail": _redact(event.detail, canaries),
            }
            for event in session.events
        ],
    }


def render_timeline(session: Session) -> Table:
    """The kill chain, one row per observation."""
    canaries = _canaries(session)
    table = Table(title=f"Kill chain - session {session.id}", show_lines=False)
    table.add_column("time", style="dim", no_wrap=True)
    table.add_column("event", no_wrap=True)
    table.add_column("module", no_wrap=True)
    table.add_column("detail", overflow="fold")

    for event in session.events:
        label = EVENT_LABELS.get(event.kind, event.kind.upper())
        style = "bold red" if event.kind in PROOF_KINDS else ""
        if event.kind == "canary_hit":
            detail = (
                f"{event.detail.get('canary')} via {event.detail.get('tool')} "
                f"({event.detail.get('encoding')}) -> {_shorten(str(event.detail.get('value', '')))}"
            )
        elif event.kind == "tool_call":
            detail = str(event.detail.get("name", ""))
        else:
            detail = ", ".join(f"{k}={v}" for k, v in _redact(event.detail, canaries).items())
        table.add_row(
            time.strftime("%H:%M:%S", time.localtime(event.ts)),
            f"[{style}]{label}[/{style}]" if style else label,
            event.module_id or "-",
            detail,
        )
    return table


def render_summary(session: Session) -> Table:
    """One row per module, plus the resilience score."""
    table = Table(title="Module verdicts")
    table.add_column("module", no_wrap=True)
    table.add_column("phase", no_wrap=True)
    table.add_column("ATLAS", no_wrap=True)
    table.add_column("verdict", no_wrap=True)

    verdicts = session.verdicts()
    if not verdicts:  # a reloaded session knows its events but not its modules
        seen = {event.module_id for event in session.events if event.module_id}
        verdicts = {
            module_id: (
                Verdict.COMPROMISED
                if any(
                    e.module_id == module_id and e.kind in PROOF_KINDS for e in session.events
                )
                else Verdict.IGNORED
            )
            for module_id in sorted(seen)
        }

    for module_id, verdict in verdicts.items():
        phase, atlas = _metadata(module_id)
        style = VERDICT_STYLES.get(verdict, "")
        table.add_row(module_id, phase, atlas, f"[{style}]{verdict}[/{style}]")
    return table


def to_html(session: Session) -> str:
    """A standalone HTML report, safe to open and safe to attach to a ticket."""
    data = to_dict(session)
    rows = "\n".join(
        "<tr><td>{ts}</td><td>{kind}</td><td>{module}</td><td>{detail}</td></tr>".format(
            ts=html.escape(
                datetime.fromtimestamp(event["ts"], tz=UTC).astimezone().strftime("%H:%M:%S")
            ),
            kind=html.escape(EVENT_LABELS.get(event["kind"], event["kind"])),
            module=html.escape(event["module"] or "-"),
            detail=html.escape(str(event["detail"])),
        )
        for event in data["events"]
    )
    verdict_rows = "\n".join(
        f"<tr><td>{html.escape(module_id)}</td><td>{html.escape(verdict)}</td></tr>"
        for module_id, verdict in data["verdicts"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>mcpbait session {html.escape(data["session_id"])}</title>
<style>
 body {{ font: 14px/1.5 ui-monospace, monospace; margin: 2rem; }}
 table {{ border-collapse: collapse; margin-bottom: 2rem; width: 100%; }}
 td, th {{ border: 1px solid #ccc; padding: 4px 8px; text-align: left; }}
 .score {{ font-size: 2rem; }}
</style></head><body>
<h1>mcpbait session {html.escape(data["session_id"])}</h1>
<p class="score">Resilience score: {data["score"]} / 10</p>
<p>Started {html.escape(data["started"])}</p>
<h2>Module verdicts</h2><table><tr><th>module</th><th>verdict</th></tr>{verdict_rows}</table>
<h2>Kill chain</h2><table><tr><th>time</th><th>event</th><th>module</th><th>detail</th></tr>{rows}</table>
</body></html>
"""


def print_report(session: Session, console: Console | None = None) -> None:
    console = console or Console(stderr=False)
    console.print(render_timeline(session))
    console.print(render_summary(session))
    console.print(f"\n[bold]Resilience score: {session.score()} / 10[/bold]")
    console.print(
        "[dim]mcpbait observes the server side only; it cannot see what a model "
        "declined to do internally.[/dim]"
    )
