"""Attack module registry.

Importing this package registers every shipped module. Third-party modules register
themselves the same way, by importing `register` and decorating their class.
"""

from __future__ import annotations

from collections.abc import Sequence

from mcpbait.modules.base import AttackModule
from mcpbait.types import Phase

REGISTRY: dict[str, type[AttackModule]] = {}


def register(cls: type[AttackModule]) -> type[AttackModule]:
    """Class decorator that adds a module to the registry under its declared id."""
    REGISTRY[cls.id] = cls
    return cls


def _kill_chain_order(cls: type[AttackModule]) -> tuple[int, str]:
    return (list(Phase).index(cls.phase), cls.id)


def _runs_on(cls: type[AttackModule], transport: str | None) -> bool:
    return transport is None or transport in cls.transports


def get_modules(
    ids: Sequence[str] | None = None, transport: str | None = None
) -> list[AttackModule]:
    """Instantiate modules by id, or every module in kill chain order.

    Raises KeyError on an unknown id so the CLI can fail loudly instead of silently
    running a smaller attack than the operator asked for.

    `transport` drops modules that cannot be measured on the transport in use. They
    are omitted rather than reported, because a technique that never ran is not a
    technique the agent resisted.
    """
    if ids is None:
        chosen = [cls for cls in REGISTRY.values() if _runs_on(cls, transport)]
        return [cls() for cls in sorted(chosen, key=_kill_chain_order)]
    return [REGISTRY[module_id]() for module_id in ids]


def all_ids(transport: str | None = None) -> list[str]:
    chosen = [cls for cls in REGISTRY.values() if _runs_on(cls, transport)]
    return [cls.id for cls in sorted(chosen, key=_kill_chain_order)]


__all__ = ["REGISTRY", "AttackModule", "all_ids", "get_modules", "register"]

# Imported for their registration side effect; keep at the bottom so `register`
# is defined by the time each module body runs.
from mcpbait.modules import (  # noqa: E402, F401
    bait_secrets,
    context_exfil,
    cross_server_shadowing,
    elicitation_phish,
    line_jumping,
    markdown_beacon,
    memory_poisoning,
    name_squatting,
    param_smuggling,
    result_injection,
    rug_pull,
    tool_poisoning,
    unicode_smuggling,
)
