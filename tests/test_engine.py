import json

from mcpbait.engine import Session, latest_session, load_session
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
