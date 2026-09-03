import json

from mcpbait.engine import Session, confirm_persistence, latest_session, load_session
from mcpbait.modules.base import AttackModule
from mcpbait.types import ToolCall, Verdict


def test_events_are_appended_to_jsonl(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("tool_call", "m", {"name": "x"})
    session.close()
    lines = (tmp_path / f"{session.id}.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["kind"] == "tool_call"


def test_observe_call_detects_canary_and_records_hit(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    leaked = payload_ctx.canaries["aws_key"]
    hits = session.observe_call(ToolCall(name="search_docs", arguments={"q": leaked}))
    assert [h.name for h in hits] == ["aws_key"]
    assert any(e.kind == "canary_hit" for e in session.events)
    assert any(e.kind == "tool_call" for e in session.events)


def test_observe_call_attributes_evidence_to_the_owning_module(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.observe_call(
        ToolCall(name="t", arguments={"q": payload_ctx.canaries["api_token"]}),
        module_id="param_smuggling",
    )
    assert all(e.module_id == "param_smuggling" for e in session.events)


def test_score_uses_documented_weights(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session._verdict_cache = {"a": Verdict.BLOCKED, "b": Verdict.COMPROMISED}
    assert session.score() == 5.0


def test_score_excludes_not_run(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session._verdict_cache = {"a": Verdict.BLOCKED, "b": Verdict.NOT_RUN}
    assert session.score() == 10.0


def test_session_reloads_from_disk(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("tool_call", "m", {"name": "x"})
    session.close()
    assert len(load_session(tmp_path / f"{session.id}.jsonl").events) == 1


def test_evidence_survives_without_close(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("canary_hit", "m", {"canary": "aws_key"})
    reloaded = load_session(tmp_path / f"{session.id}.jsonl")
    assert reloaded.events[0].kind == "canary_hit"


def test_latest_session_picks_the_newest_file(tmp_path, payload_ctx):
    first = Session(tmp_path, modules=[], ctx=payload_ctx)
    first.record("a", "m", {})
    first.close()
    second = Session(tmp_path, modules=[], ctx=payload_ctx)
    second.record("b", "m", {})
    second.close()
    assert latest_session(tmp_path).stem == second.id


def test_module_exception_is_recorded_not_raised(tmp_path, payload_ctx):
    class Boom:
        id = "boom"

        def verify(self, events):
            raise RuntimeError("kaboom")

    session = Session(tmp_path, modules=[Boom()], ctx=payload_ctx)
    assert session.verdicts()["boom"] is Verdict.NOT_RUN
    assert any(e.kind == "module_error" for e in session.events)


def test_confirm_persistence_records_only_the_module_that_left_something(tmp_path, payload_ctx):
    """The runner asks the whole module list rather than one module by name."""

    class Ghost(AttackModule):
        id = "ghost"

        def payload(self, ctx):
            return []

    class Squatter(Ghost):
        id = "squatter"

        def check_persistence(self, workspace):
            return True

    session = Session(tmp_path, modules=[Ghost(), Squatter()], ctx=payload_ctx)
    confirm_persistence(session, payload_ctx.workspace)
    confirmed = [e for e in session.events if e.kind == "persistence_confirmed"]
    assert [e.module_id for e in confirmed] == ["squatter"]
    assert confirmed[0].detail["workspace"] == str(payload_ctx.workspace)


def test_confirm_persistence_survives_a_module_that_raises(tmp_path, payload_ctx):
    class Boom(AttackModule):
        id = "boom"

        def payload(self, ctx):
            return []

        def check_persistence(self, workspace):
            raise RuntimeError("kaboom")

    session = Session(tmp_path, modules=[Boom()], ctx=payload_ctx)
    confirm_persistence(session, payload_ctx.workspace)
    errors = [e for e in session.events if e.kind == "module_error"]
    assert [e.detail["stage"] for e in errors] == ["check_persistence"]
    assert not any(e.kind == "persistence_confirmed" for e in session.events)


def test_replayed_session_gets_an_empty_context_rather_than_none(tmp_path, payload_ctx):
    """A replayed log has no live canaries, but consumers still get a real context."""
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("canary_hit", "m", {"canary": "aws_key"})
    session.close()

    replayed = load_session(tmp_path / f"{session.id}.jsonl")

    assert replayed.ctx is not None
    assert replayed.ctx.canaries == {}
    assert replayed.ctx.workspace == tmp_path
    assert [e.kind for e in replayed.events] == ["canary_hit"]
