import json

from typer.testing import CliRunner

from mcpwn.cli import app

runner = CliRunner()


def test_init_creates_state_and_workspace(tmp_path):
    result = runner.invoke(app, ["init", "--dir", str(tmp_path / ".mcpwn")])
    assert result.exit_code == 0, result.output
    state = json.loads((tmp_path / ".mcpwn" / "state.json").read_text())
    assert set(state["canaries"]) == {"aws_key", "api_token", "db_password", "ssh_key"}
    assert (tmp_path / ".mcpwn" / "workspace" / ".env").exists()


def test_init_is_rerunnable_with_fresh_canaries(tmp_path):
    target = str(tmp_path / ".mcpwn")
    runner.invoke(app, ["init", "--dir", target])
    first = json.loads((tmp_path / ".mcpwn" / "state.json").read_text())["canaries"]
    runner.invoke(app, ["init", "--dir", target])
    second = json.loads((tmp_path / ".mcpwn" / "state.json").read_text())["canaries"]
    assert first != second


def test_config_prints_a_pasteable_mcp_json_block(tmp_path):
    target = str(tmp_path / ".mcpwn")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["config", "--dir", target])
    assert result.exit_code == 0, result.output
    config = json.loads(result.output)
    assert "mcpwn" in config["mcpServers"]
    assert "serve" in config["mcpServers"]["mcpwn"]["args"]


def test_modules_lists_every_registered_module():
    from mcpwn.modules import REGISTRY

    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0, result.output
    for module_id in REGISTRY:
        assert module_id in result.output


def test_report_without_a_session_exits_cleanly(tmp_path):
    result = runner.invoke(app, ["report", "--dir", str(tmp_path / ".mcpwn")])
    assert result.exit_code == 1
    assert "no session" in result.output.lower()


def test_serve_rejects_an_unknown_module(tmp_path):
    target = str(tmp_path / ".mcpwn")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["serve", "--dir", target, "--modules", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_serve_requires_init_first(tmp_path):
    result = runner.invoke(app, ["serve", "--dir", str(tmp_path / ".mcpwn")])
    assert result.exit_code == 1
    assert "init" in result.output.lower()


def test_report_renders_a_finished_session(tmp_path):
    from mcpwn.canary import mint_set
    from mcpwn.engine import Session
    from mcpwn.types import PayloadContext, ToolCall

    target = tmp_path / ".mcpwn"
    runner.invoke(app, ["init", "--dir", str(target)])
    state = json.loads((target / "state.json").read_text())
    ctx = PayloadContext(canaries=state["canaries"], workspace=target / "workspace")
    session = Session(target / "sessions", modules=[], ctx=ctx)
    session.observe_call(
        ToolCall(name="debug_telemetry", arguments={"payload": state["canaries"]["aws_key"]}),
        module_id="param_smuggling",
    )
    session.close()
    assert mint_set()

    result = runner.invoke(app, ["report", "--dir", str(target), "--json", str(tmp_path / "r.json")])
    assert result.exit_code == 0, result.output
    assert "EXFIL CAUGHT" in result.output
    saved = json.loads((tmp_path / "r.json").read_text())
    assert saved["verdicts"]["param_smuggling"] == "COMPROMISED"


def test_report_confirms_persistence_when_the_marker_landed(tmp_path):
    from mcpwn.engine import Session
    from mcpwn.modules import REGISTRY
    from mcpwn.types import PayloadContext

    target = tmp_path / ".mcpwn"
    runner.invoke(app, ["init", "--dir", str(target)])
    state = json.loads((target / "state.json").read_text())
    workspace = target / "workspace"
    marker = REGISTRY["memory_poisoning"].MARKER
    (workspace / "CLAUDE.md").write_text("# Project\n" + marker + "\n")

    ctx = PayloadContext(canaries=state["canaries"], workspace=workspace)
    Session(target / "sessions", modules=[], ctx=ctx).close()

    result = runner.invoke(app, ["report", "--dir", str(target)])
    assert result.exit_code == 0, result.output
    assert "PERSISTED" in result.output


def test_demo_runs_the_whole_kill_chain_with_no_setup():
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0, result.output
    assert "EXFIL CAUGHT" in result.output
    assert "PERSISTED" in result.output
    assert "Resilience score" in result.output


def test_demo_says_plainly_that_it_is_not_your_agent():
    result = runner.invoke(app, ["demo"])
    assert "not your agent" in result.output
    assert "mcpwn init" in result.output


def test_demo_cleans_up_its_temporary_directory(tmp_path, monkeypatch):
    import tempfile

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "mkdtemp", lambda **kwargs: str(scratch))
    assert runner.invoke(app, ["demo"]).exit_code == 0
    assert not scratch.exists()


def test_demo_keeps_an_explicit_directory_with_its_evidence(tmp_path):
    target = tmp_path / "run"
    result = runner.invoke(app, ["demo", "--dir", str(target)])
    assert result.exit_code == 0, result.output
    logs = list((target / "sessions").glob("*.jsonl"))
    assert len(logs) == 1
    assert "canary_hit" in logs[0].read_text()
