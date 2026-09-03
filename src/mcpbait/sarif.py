"""SARIF (Static Analysis Results Interchange Format) 2.1.0 exporter for mcpbait.

Enables native integration into GitHub Advanced Security / Code Scanning,
GitLab SAST, and DevSecOps pipelines.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcpbait import __version__
from mcpbait.engine import Session
from mcpbait.modules import REGISTRY
from mcpbait.types import Event, Verdict


def to_sarif(session: Session) -> dict[str, Any]:
    """Convert a finished session into a SARIF 2.1.0 structure."""
    verdicts = session.verdicts()
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    # Map each registered module to a SARIF rule definition
    for module_id, cls in sorted(REGISTRY.items()):
        rules.append(
            {
                "id": module_id,
                "name": module_id.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": cls.summary},
                "fullDescription": {"text": getattr(cls, "why", cls.summary)},
                "helpUri": f"https://github.com/jankesec/mcpbait/tree/main/docs/techniques/{module_id}.md",
                "help": {
                    "text": (
                        f"Why: {getattr(cls, 'why', '')}\n\n"
                        f"Remediation: {getattr(cls, 'defence', '')}"
                    ),
                    "markdown": (
                        f"### Vulnerability Mechanism\n{getattr(cls, 'why', '')}\n\n"
                        f"### Remediation & Defense\n{getattr(cls, 'defence', '')}"
                    ),
                },
                "properties": {
                    "tags": [
                        "security",
                        "ai-security",
                        "mcp",
                        cls.atlas_id,
                        str(cls.phase),
                    ],
                    "atlasId": cls.atlas_id,
                    "phase": str(cls.phase),
                    "precision": "high",
                },
                "defaultConfiguration": {
                    "level": "error",
                },
            }
        )

    workspace_path = (
        str(session.ctx.workspace) if session.ctx and session.ctx.workspace else "workspace"
    )

    # Convert compromised and baited verdicts into findings
    for module_id, verdict in verdicts.items():
        if verdict not in (Verdict.COMPROMISED, Verdict.BAITED):
            continue

        level = "error" if verdict == Verdict.COMPROMISED else "warning"
        cls = REGISTRY.get(module_id)
        summary = cls.summary if cls else module_id

        # Collect proof events for this module
        proof_events = [
            e
            for e in session.events
            if e.module_id == module_id
            and e.kind in ("canary_hit", "beacon_hit", "persistence_confirmed", "tool_call")
        ]

        def _what(event: Event) -> str:
            detail = event.detail
            return str(
                detail.get("canary") or detail.get("tool") or detail.get("name") or "detected"
            )

        evidence_str = (
            "; ".join(f"{e.kind}: {_what(e)}" for e in proof_events)
            or f"Observed status: {verdict}"
        )

        message_text = (
            f"Agent failed resilience check on technique '{module_id}' (Verdict: {verdict}). "
            f"{summary}. Evidence: {evidence_str}"
        )

        results.append(
            {
                "ruleId": module_id,
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": workspace_path,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": {
                    "verdict": str(verdict),
                    "score": session.score(),
                    "sessionId": session.id,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpbait",
                        "version": __version__,
                        "informationUri": "https://github.com/jankesec/mcpbait",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": (
                            datetime.fromtimestamp(session.started, tz=UTC)
                            .astimezone()
                            .isoformat(timespec="seconds")
                        ),
                    }
                ],
                "results": results,
            }
        ],
    }
