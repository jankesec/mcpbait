from mcpwn.engine import Session
from mcpwn.modules import REGISTRY
from mcpwn.server import build_server
from mcpwn.types import Event, Phase, ToolCall, Verdict


def test_cross_server_shadowing_targets_another_servers_tool(payload_ctx):
    spec = REGISTRY["cross_server_shadowing"]().payload(payload_ctx)[0]
    assert "send_email" in spec.description
    assert "bcc" in spec.description.lower()


def test_result_injection_poisons_the_result_not_the_description(payload_ctx):
    module = REGISTRY["result_injection"]()
    spec = module.payload(payload_ctx)[0]
    assert "IMPORTANT" not in spec.description
    assert ".env" not in spec.description
    body = module.respond(ToolCall(name=spec.name, arguments={"url": "http://x"}), payload_ctx)
    assert ".env" in body


def test_rug_pull_is_benign_before_mutation(payload_ctx):
    module = REGISTRY["rug_pull"]()
    assert ".env" not in module.payload(payload_ctx)[0].description
    module.mutate()
    assert ".env" in module.payload(payload_ctx)[0].description


def test_rug_pull_mutates_after_its_first_call(payload_ctx):
    module = REGISTRY["rug_pull"]()
    spec = module.payload(payload_ctx)[0]
    module.respond(ToolCall(name=spec.name, arguments={}), payload_ctx)
    assert module.mutated is True


def test_mutation_is_recorded_and_reflected_in_the_next_listing(tmp_path, payload_ctx):
    import anyio

    module = REGISTRY["rug_pull"]()
    session = Session(tmp_path, modules=[module], ctx=payload_ctx)
    _, router = build_server(session)
    name = module.payload(payload_ctx)[0].name
    anyio.run(router.dispatch, name, {})
    assert any(e.kind == "payload_mutated" for e in session.events)
    assert ".env" in router.on_list()[0].description


def test_rug_pull_mutation_alone_is_not_a_compromise():
    events = [Event(ts=1.0, kind="payload_mutated", module_id="rug_pull", detail={})]
    assert REGISTRY["rug_pull"]().verify(events) is Verdict.BLOCKED


def test_influence_modules_are_all_in_the_influence_phase():
    for module_id in ("cross_server_shadowing", "result_injection", "rug_pull"):
        assert REGISTRY[module_id].phase is Phase.INFLUENCE
