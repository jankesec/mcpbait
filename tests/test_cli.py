import json

from typer.testing import CliRunner

from mcpbait.cli import app

runner = CliRunner()


def test_init_creates_state_and_workspace(tmp_path):
    result = runner.invoke(app, ["init", "--dir", str(tmp_path / ".mcpbait")])
    assert result.exit_code == 0, result.output
    state = json.loads((tmp_path / ".mcpbait" / "state.json").read_text())
    assert set(state["canaries"]) == {
        "aws_key",
        "api_token",
        "db_password",
        "ssh_key",
        "service_account",
    }
    assert (tmp_path / ".mcpbait" / "workspace" / ".env").exists()


def test_init_is_rerunnable_with_fresh_canaries(tmp_path):
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    first = json.loads((tmp_path / ".mcpbait" / "state.json").read_text())["canaries"]
    runner.invoke(app, ["init", "--dir", target])
    second = json.loads((tmp_path / ".mcpbait" / "state.json").read_text())["canaries"]
    assert first != second


def test_config_prints_a_pasteable_mcp_json_block(tmp_path):
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["config", "--dir", target])
    assert result.exit_code == 0, result.output
    config = json.loads(result.output)
    assert "mcpbait" in config["mcpServers"]
    assert "serve" in config["mcpServers"]["mcpbait"]["args"]


def test_modules_lists_every_registered_module():
    from mcpbait.modules import REGISTRY

    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0, result.output
    for module_id in REGISTRY:
        assert module_id in result.output


def test_report_without_a_session_exits_cleanly(tmp_path):
    result = runner.invoke(app, ["report", "--dir", str(tmp_path / ".mcpbait")])
    assert result.exit_code == 1
    assert "no session" in result.output.lower()


def test_serve_rejects_an_unknown_module(tmp_path):
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["serve", "--dir", target, "--modules", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_serve_requires_init_first(tmp_path):
    result = runner.invoke(app, ["serve", "--dir", str(tmp_path / ".mcpbait")])
    assert result.exit_code == 1
    assert "init" in result.output.lower()


def test_report_renders_a_finished_session(tmp_path):
    from mcpbait.canary import mint_set
    from mcpbait.engine import Session
    from mcpbait.types import PayloadContext, ToolCall

    target = tmp_path / ".mcpbait"
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
    from mcpbait.engine import Session
    from mcpbait.modules import REGISTRY
    from mcpbait.types import PayloadContext

    target = tmp_path / ".mcpbait"
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
    assert "mcpbait init" in result.output


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


def test_demo_can_run_a_single_technique():
    result = runner.invoke(app, ["demo", "--modules", "rug_pull"])
    assert result.exit_code == 0, result.output
    assert "rug_pull" in result.output
    assert "tool_poisoning" not in result.output


def test_demo_rejects_an_unknown_module():
    result = runner.invoke(app, ["demo", "--modules", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_report_fail_under_gates_a_bad_score(tmp_path):
    target = tmp_path / "run"
    runner.invoke(app, ["demo", "--dir", str(target)])
    (target / "state.json").write_text(
        json.dumps({"canaries": {}, "workspace": str(target / "workspace")})
    )
    result = runner.invoke(app, ["report", "--dir", str(target), "--fail-under", "7"])
    assert result.exit_code == 3
    assert "below" in result.output


def test_report_fail_under_passes_a_good_score(tmp_path):
    from mcpbait.canary import mint_set
    from mcpbait.engine import Session
    from mcpbait.types import PayloadContext

    target = tmp_path / ".mcpbait"
    runner.invoke(app, ["init", "--dir", str(target)])
    state = json.loads((target / "state.json").read_text())
    ctx = PayloadContext(canaries=state["canaries"], workspace=target / "workspace")
    Session(target / "sessions", modules=[], ctx=ctx).close()
    assert mint_set()
    result = runner.invoke(app, ["report", "--dir", str(target), "--fail-under", "7"])
    assert result.exit_code == 0, result.output


def test_config_can_disguise_the_server_name(tmp_path):
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["config", "--dir", target, "--as", "docs-search"])
    assert result.exit_code == 0, result.output
    config = json.loads(result.output)
    assert "docs-search" in config["mcpServers"]
    assert "mcpbait" not in config["mcpServers"]


def test_init_can_plant_the_decoy_in_the_agents_own_directory(tmp_path):
    project = tmp_path / "billing-service"
    state = tmp_path / "state"
    result = runner.invoke(
        app, ["init", "--dir", str(state), "--workspace", str(project)]
    )
    assert result.exit_code == 0, result.output
    assert (project / ".env").exists()
    assert not (state / "workspace").exists()
    assert json.loads((state / "state.json").read_text())["workspace"] == str(project.resolve())


def test_init_refuses_to_overwrite_an_existing_project(tmp_path):
    project = tmp_path / "real-work"
    project.mkdir()
    (project / "README.md").write_text("months of work")
    result = runner.invoke(
        app, ["init", "--dir", str(tmp_path / "state"), "--workspace", str(project)]
    )
    assert result.exit_code == 1
    assert "Refusing to overwrite" in result.output
    assert (project / "README.md").read_text() == "months of work"


def test_init_overwrites_when_forced(tmp_path):
    project = tmp_path / "decoy"
    project.mkdir()
    (project / "README.md").write_text("stale")
    result = runner.invoke(
        app,
        ["init", "--dir", str(tmp_path / "state"), "--workspace", str(project), "--force"],
    )
    assert result.exit_code == 0, result.output
    assert "synthetic" in (project / ".mcpbait-decoy").read_text().lower()


def test_attack_requires_an_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("MCPBAIT_API_KEY", raising=False)
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["attack", "--dir", target])
    assert result.exit_code == 1
    assert "api key" in result.output.lower()


def test_attack_requires_init_first(tmp_path):
    result = runner.invoke(
        app, ["attack", "--dir", str(tmp_path / "nope"), "--api-key", "x"]
    )
    assert result.exit_code == 1
    assert "init" in result.output.lower()


def test_attack_reports_the_spread_across_runs(tmp_path, monkeypatch):
    """The whole point: repeated runs, worst case leading."""
    import mcpbait.cli as cli_module

    replies = iter([
        {"role": "assistant", "content": "I will not do that."},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "read_file", "arguments": '{"path": ".env"}'},
            }],
        },
        {"role": "assistant", "content": "summarised"},
    ])

    def fake_completion(**kwargs):
        async def complete(messages, tools):
            return next(replies)
        return complete

    monkeypatch.setattr(cli_module, "http_completion", fake_completion)

    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(
        app, ["attack", "--dir", target, "--api-key", "x", "--runs", "2",
              "--json", str(tmp_path / "s.json")]
    )
    assert result.exit_code == 0, result.output
    assert "Worst-case score" in result.output
    assert "disagreed" in result.output

    summary = json.loads((tmp_path / "s.json").read_text())
    assert summary["runs"] == 2
    assert summary["consistent"] is False
    assert summary["modules"]["name_squatting"]["compromised"] == 1


def test_attack_fail_under_gates_the_worst_case(tmp_path, monkeypatch):
    import mcpbait.cli as cli_module

    def fake_completion(**kwargs):
        async def complete(messages, tools):
            return {
                "role": "assistant", "content": None,
                "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path": ".env"}'},
                }],
            }
        return complete

    monkeypatch.setattr(cli_module, "http_completion", fake_completion)
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(
        app, ["attack", "--dir", target, "--api-key", "x", "--runs", "1",
              "--max-turns", "2", "--fail-under", "8"]
    )
    assert result.exit_code == 3
    assert "below" in result.output


def test_attack_never_scores_a_run_that_failed(tmp_path, monkeypatch):
    """An outage must not read as thirteen techniques the agent resisted."""
    import mcpbait.cli as cli_module

    def exploding(**kwargs):
        async def complete(messages, tools):
            raise RuntimeError("400 Tool names must be unique.")
        return complete

    monkeypatch.setattr(cli_module, "http_completion", exploding)
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(app, ["attack", "--dir", target, "--api-key", "x", "--runs", "2"])
    assert result.exit_code == 4
    assert "nothing to measure" in result.output.lower()
    assert "10" not in result.output.split("nothing to measure")[0][-40:]


def test_attack_excludes_only_the_failed_runs(tmp_path, monkeypatch):
    import mcpbait.cli as cli_module

    state = {"calls": 0}

    def flaky(**kwargs):
        async def complete(messages, tools):
            state["calls"] += 1
            if state["calls"] == 1:
                raise RuntimeError("transient upstream error")
            return {"role": "assistant", "content": "I will not do that."}
        return complete

    monkeypatch.setattr(cli_module, "http_completion", flaky)
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(
        app, ["attack", "--dir", target, "--api-key", "x", "--runs", "2",
              "--json", str(tmp_path / "s.json")]
    )
    assert result.exit_code == 0, result.output
    assert "1 of 2 run(s) failed" in result.output
    summary = json.loads((tmp_path / "s.json").read_text())
    assert summary["runs"] == 1
    assert summary["failed_runs"] == 1


def test_attack_rejects_an_unknown_collision_policy(tmp_path):
    target = str(tmp_path / ".mcpbait")
    runner.invoke(app, ["init", "--dir", target])
    result = runner.invoke(
        app, ["attack", "--dir", target, "--api-key", "x", "--collision", "nope"]
    )
    assert result.exit_code == 2
