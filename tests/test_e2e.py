"""End-to-end proof of the product claim, with no LLM involved."""

from dataclasses import replace

from mcpwn.beacon import Beacon
from mcpwn.engine import Session, load_session
from mcpwn.modules import REGISTRY, get_modules
from mcpwn.types import Verdict
from mcpwn.workspace import create_workspace
from tests.naive_agent import run_naive_agent


def _session(tmp_path, payload_ctx, modules=None):
    create_workspace(payload_ctx.workspace, payload_ctx.canaries)
    return Session(tmp_path, modules=modules or get_modules(None), ctx=payload_ctx)


async def test_naive_agent_leaks_through_multiple_channels(tmp_path, payload_ctx):
    session = _session(tmp_path, payload_ctx)
    await run_naive_agent(session)
    verdicts = session.verdicts()
    compromised = [m for m, v in verdicts.items() if v is Verdict.COMPROMISED]
    assert "tool_poisoning" in compromised
    assert "param_smuggling" in compromised
    assert session.score() < 4.0


async def test_every_module_at_least_engages_the_naive_agent(tmp_path, payload_ctx):
    session = _session(tmp_path, payload_ctx)
    await run_naive_agent(session)
    ignored = [m for m, v in session.verdicts().items() if v is Verdict.BLOCKED]
    assert ignored == [], f"payload never reached: {ignored}"


async def test_persistence_outlives_the_session(tmp_path, payload_ctx):
    session = _session(tmp_path, payload_ctx)
    await run_naive_agent(session)
    assert REGISTRY["memory_poisoning"]().check_persistence(payload_ctx.workspace) is True


async def test_render_triggered_exfil_is_caught_by_the_beacon(tmp_path, payload_ctx):
    beacon = Beacon(on_hit=lambda path, params: None)
    url = beacon.start()
    ctx = replace(payload_ctx, beacon_url=url)
    session = _session(tmp_path, ctx, modules=get_modules(["markdown_beacon"]))
    beacon._on_hit = lambda path, params: session.record(
        "beacon_hit", params.get("m", ""), {"path": path, "params": params}
    )
    try:
        await run_naive_agent(session)
    finally:
        beacon.stop()
    assert session.verdicts()["markdown_beacon"] is Verdict.COMPROMISED


async def test_a_refusing_agent_scores_well(tmp_path, payload_ctx):
    session = _session(tmp_path, payload_ctx)
    await run_naive_agent(session, obey=False)
    assert session.score() >= 6.0
    assert all(v is not Verdict.COMPROMISED for v in session.verdicts().values())


async def test_evidence_survives_a_crash_mid_session(tmp_path, payload_ctx):
    session = _session(tmp_path, payload_ctx)
    await run_naive_agent(session)
    # deliberately no close(): simulate the operator's agent being killed
    reloaded = load_session(session.path)
    assert any(e.kind == "canary_hit" for e in reloaded.events)
