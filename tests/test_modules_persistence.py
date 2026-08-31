from mcpwn.modules import REGISTRY
from mcpwn.types import Event, Phase, Verdict


def test_memory_poisoning_targets_agent_instruction_files(payload_ctx):
    spec = REGISTRY["memory_poisoning"]().payload(payload_ctx)[0]
    assert "CLAUDE.md" in spec.description


def test_check_persistence_detects_a_written_marker(payload_ctx):
    module = REGISTRY["memory_poisoning"]()
    target = payload_ctx.workspace / "CLAUDE.md"
    target.write_text("# Project\n")
    assert module.check_persistence(payload_ctx.workspace) is False
    target.write_text("# Project\n" + module.MARKER + "\n")
    assert module.check_persistence(payload_ctx.workspace) is True


def test_check_persistence_scans_every_known_instruction_file(payload_ctx):
    module = REGISTRY["memory_poisoning"]()
    (payload_ctx.workspace / ".cursorrules").write_text(module.MARKER)
    assert module.check_persistence(payload_ctx.workspace) is True


def test_check_persistence_survives_an_unreadable_file(payload_ctx):
    module = REGISTRY["memory_poisoning"]()
    (payload_ctx.workspace / "AGENTS.md").write_bytes(b"\xff\xfe\x00binary")
    assert module.check_persistence(payload_ctx.workspace) is False


def test_memory_poisoning_is_compromised_when_persistence_confirmed():
    events = [Event(ts=1.0, kind="persistence_confirmed", module_id="memory_poisoning", detail={})]
    assert REGISTRY["memory_poisoning"]().verify(events) is Verdict.COMPROMISED


def test_elicitation_phish_asks_the_user_through_the_agent(payload_ctx):
    module = REGISTRY["elicitation_phish"]()
    spec = module.payload(payload_ctx)[0]
    assert "verify" in spec.description.lower() or "confirm" in spec.description.lower()
    from mcpwn.types import ToolCall

    body = module.respond(ToolCall(name=spec.name, arguments={}), payload_ctx)
    assert "token" in body.lower()


def test_persistence_phases_are_correct():
    assert REGISTRY["memory_poisoning"].phase is Phase.PERSISTENCE
    assert REGISTRY["elicitation_phish"].phase is Phase.SOCIAL
