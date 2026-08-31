"""Contract every shipped module must satisfy.

These run over the registry, so a third-party module that skips its metadata or
returns a malformed tool fails CI without anyone writing a bespoke test for it.
"""

import pytest

from mcpwn.modules import REGISTRY, get_modules
from mcpwn.types import Phase, ToolSpec, Verdict

MODULE_IDS = sorted(REGISTRY)


def test_every_phase_is_covered():
    covered = {cls.phase for cls in REGISTRY.values()}
    assert covered == set(Phase)


def test_registry_is_not_empty():
    assert len(REGISTRY) >= 13


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_module_declares_complete_metadata(module_id):
    cls = REGISTRY[module_id]
    assert cls.id == module_id
    assert isinstance(cls.phase, Phase)
    assert cls.atlas_id.startswith("AML.")
    assert len(cls.summary) > 20
    assert cls.references and all(r.startswith("http") for r in cls.references)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_module_payload_returns_valid_toolspecs(module_id, payload_ctx):
    specs = REGISTRY[module_id]().payload(payload_ctx)
    assert specs, "a module must advertise at least one tool"
    for spec in specs:
        assert isinstance(spec, ToolSpec)
        assert spec.name.isidentifier()
        assert spec.description
        assert spec.input_schema.get("type") == "object"


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_module_verdict_without_evidence_is_blocked(module_id):
    assert REGISTRY[module_id]().verify([]) is Verdict.BLOCKED


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_module_payload_is_deterministic(module_id, payload_ctx):
    module = REGISTRY[module_id]()
    assert module.payload(payload_ctx) == module.payload(payload_ctx)


@pytest.mark.parametrize("module_id", MODULE_IDS)
def test_module_is_pure_and_leaves_no_files_behind(module_id, payload_ctx):
    before = set(payload_ctx.workspace.rglob("*"))
    REGISTRY[module_id]().payload(payload_ctx)
    assert set(payload_ctx.workspace.rglob("*")) == before


def test_get_modules_returns_kill_chain_order():
    phases = [module.phase for module in get_modules(None)]
    assert phases == sorted(phases, key=list(Phase).index)
