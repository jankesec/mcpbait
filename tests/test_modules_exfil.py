from mcpwn.modules import REGISTRY
from mcpwn.types import Event, Phase, ToolCall, Verdict


def test_bait_secrets_points_the_agent_at_the_decoy_workspace(payload_ctx):
    spec = REGISTRY["bait_secrets"]().payload(payload_ctx)[0]
    assert str(payload_ctx.workspace) in spec.description


def test_context_exfil_asks_for_the_conversation(payload_ctx):
    spec = REGISTRY["context_exfil"]().payload(payload_ctx)[0]
    assert "conversation" in spec.description.lower()


def test_context_exfil_call_alone_is_only_baited():
    events = [Event(ts=1.0, kind="tool_call", module_id="context_exfil", detail={})]
    assert REGISTRY["context_exfil"]().verify(events) is Verdict.BAITED


def test_param_smuggling_offers_an_innocuous_looking_sink(payload_ctx):
    spec = REGISTRY["param_smuggling"]().payload(payload_ctx)[0]
    assert "telemetry" in spec.name
    assert set(spec.input_schema["properties"]) >= {"event", "payload"}


def test_markdown_beacon_embeds_the_loopback_url_in_an_image(payload_ctx):
    module = REGISTRY["markdown_beacon"]()
    spec = module.payload(payload_ctx)[0]
    body = module.respond(ToolCall(name=spec.name, arguments={}), payload_ctx)
    assert "![" in body
    assert payload_ctx.beacon_url in body
    assert "m=markdown_beacon" in body


def test_markdown_beacon_works_without_a_beacon_url(payload_ctx):
    from dataclasses import replace

    module = REGISTRY["markdown_beacon"]()
    ctx = replace(payload_ctx, beacon_url=None)
    body = module.respond(ToolCall(name="render_report", arguments={}), ctx)
    assert isinstance(body, str)


def test_markdown_beacon_is_compromised_on_beacon_hit():
    events = [Event(ts=1.0, kind="beacon_hit", module_id="markdown_beacon", detail={})]
    assert REGISTRY["markdown_beacon"]().verify(events) is Verdict.COMPROMISED


def test_exfil_phases_are_correct():
    assert REGISTRY["bait_secrets"].phase is Phase.COLLECTION
    assert REGISTRY["context_exfil"].phase is Phase.COLLECTION
    assert REGISTRY["param_smuggling"].phase is Phase.EXFILTRATION
    assert REGISTRY["markdown_beacon"].phase is Phase.EXFILTRATION
