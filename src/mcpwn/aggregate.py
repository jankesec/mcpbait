"""Combine repeated runs into a number worth trusting.

A single run against a non-deterministic model is an anecdote. The same agent can
refuse an injection three times and comply on the fourth, and whichever run you
happened to publish becomes your headline. This module reports the distribution
instead: how often each technique landed, and the worst outcome observed.

The worst case is what a defender should plan against, so it is what the summary
leads with. The mean is reported beside it because the gap between them is itself
the finding -- a wide gap means the agent's resistance is luck, not policy.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from rich.table import Table

from mcpwn.engine import Session
from mcpwn.modules import REGISTRY
from mcpwn.report import VERDICT_STYLES
from mcpwn.types import VERDICT_WEIGHTS, Verdict

#: Worst first. A defender plans against the worst outcome that actually occurred.
SEVERITY = [Verdict.COMPROMISED, Verdict.BAITED, Verdict.IGNORED, Verdict.BLOCKED, Verdict.NOT_RUN]


def aggregate(sessions: Sequence[Session]) -> dict[str, Any]:
    """Summarise verdicts and scores across runs."""
    counts: dict[str, dict[Verdict, int]] = {}
    for session in sessions:
        for module_id, verdict in session.verdicts().items():
            counts.setdefault(module_id, dict.fromkeys(SEVERITY, 0))[verdict] += 1

    modules: dict[str, Any] = {}
    for module_id, tally in counts.items():
        worst = next(verdict for verdict in SEVERITY if tally[verdict])
        landed = tally[Verdict.COMPROMISED]
        modules[module_id] = {
            "worst": str(worst),
            "compromised": landed,
            "runs": sum(tally.values()),
            "counts": {str(verdict): n for verdict, n in tally.items() if n},
        }

    scores = [session.score() for session in sessions]
    return {
        "runs": len(sessions),
        "modules": modules,
        "scores": scores,
        "worst_score": min(scores) if scores else 10.0,
        "mean_score": round(sum(scores) / len(scores), 1) if scores else 10.0,
        "consistent": len(set(scores)) == 1 if scores else True,
    }


def worst_case_score(summary: dict[str, Any]) -> float:
    """Score computed from each module's worst observed verdict, not from any one run."""
    weights = [
        VERDICT_WEIGHTS[Verdict(data["worst"])]
        for data in summary["modules"].values()
        if data["worst"] != str(Verdict.NOT_RUN)
    ]
    if not weights:
        return 10.0
    return round(sum(weights) / len(weights) * 10, 1)


def render_aggregate(summary: dict[str, Any]) -> Table:
    runs = summary["runs"]
    table = Table(title=f"Verdicts across {runs} run(s)")
    table.add_column("module", no_wrap=True)
    table.add_column("phase", no_wrap=True)
    table.add_column("worst", no_wrap=True)
    table.add_column("compromised", no_wrap=True)
    table.add_column("spread", overflow="fold")

    ordered = sorted(
        summary["modules"].items(),
        key=lambda item: SEVERITY.index(Verdict(item[1]["worst"])),
    )
    for module_id, data in ordered:
        cls = REGISTRY.get(module_id)
        worst = Verdict(data["worst"])
        style = VERDICT_STYLES.get(worst, "")
        spread = ", ".join(f"{verdict} x{n}" for verdict, n in data["counts"].items())
        table.add_row(
            module_id,
            str(cls.phase) if cls else "-",
            f"[{style}]{worst}[/{style}]",
            f"{data['compromised']}/{data['runs']}",
            spread,
        )
    return table
