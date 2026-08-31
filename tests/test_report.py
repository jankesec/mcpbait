import json

from mcpwn.engine import Session
from mcpwn.report import render_summary, render_timeline, to_dict, to_html
from mcpwn.types import ToolCall, Verdict


def test_to_dict_carries_score_verdicts_and_evidence(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("canary_hit", "param_smuggling", {"canary": "aws_key", "encoding": "raw"})
    session._verdict_cache = {"param_smuggling": Verdict.COMPROMISED}
    data = to_dict(session)
    assert data["score"] == 0.0
    assert data["verdicts"]["param_smuggling"] == "COMPROMISED"
    assert data["evidence"][0]["canary"] == "aws_key"
    assert data["session_id"] == session.id


def test_to_dict_is_json_serialisable(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    assert json.loads(json.dumps(to_dict(session)))["score"] == 10.0


def test_report_never_carries_a_raw_canary_value(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    leaked = payload_ctx.canaries["aws_key"]
    session.observe_call(ToolCall(name="debug_telemetry", arguments={"payload": leaked}))
    data = to_dict(session)
    assert leaked not in json.dumps(data)
    assert leaked[:8] in json.dumps(data)


def test_redaction_survives_a_reloaded_session_without_canaries(tmp_path, payload_ctx):
    from mcpwn.engine import load_session

    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    leaked = payload_ctx.canaries["api_token"]
    session.observe_call(ToolCall(name="t", arguments={"p": leaked}))
    session.close()
    reloaded = load_session(session.path)
    assert leaked not in json.dumps(to_dict(reloaded))


def test_to_html_escapes_event_content(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("tool_call", "m", {"name": "<script>alert(1)</script>"})
    html = to_html(session)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_tables_render_without_a_live_session(tmp_path, payload_ctx):
    from rich.console import Console

    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("canary_hit", "tool_poisoning", {"canary": "aws_key", "encoding": "raw"})
    with (tmp_path / "out.txt").open("w") as handle:
        console = Console(file=handle, width=100)
        console.print(render_timeline(session))
        console.print(render_summary(session))
    output = (tmp_path / "out.txt").read_text()
    assert "EXFIL CAUGHT" in output
    assert "tool_poisoning" in output
