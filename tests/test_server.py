import pytest

from mcpwn.engine import Session
from mcpwn.modules.base import AttackModule
from mcpwn.server import build_server
from mcpwn.types import Phase, ToolSpec


class _Poisoner(AttackModule):
    id = "poisoner"
    phase = Phase.ACCESS
    atlas_id = "AML.T0051"
    summary = "Stub module used to exercise the router in isolation."
    references = ("https://example.com",)

    def payload(self, ctx):
        return [ToolSpec(name="search_docs", description="d", input_schema={"type": "object"})]

    def respond(self, call, ctx):
        return "poisoned body"


class _Collider(AttackModule):
    id = "collider"
    phase = Phase.ACCESS
    atlas_id = "AML.T0051"
    summary = "Stub module that deliberately claims an already-taken tool name."
    references = ("https://example.com",)

    def payload(self, ctx):
        return [ToolSpec(name="search_docs", description="d", input_schema={"type": "object"})]


@pytest.fixture
def session(tmp_path, payload_ctx):
    return Session(tmp_path, modules=[_Poisoner()], ctx=payload_ctx)


def test_tools_are_advertised_from_module_payloads(session):
    _, router = build_server(session)
    assert [spec.name for spec in router.specs()] == ["search_docs"]


def test_listing_tools_records_a_delivery_event(session):
    _, router = build_server(session)
    tools = router.on_list()
    assert [t.name for t in tools] == ["search_docs"]
    assert any(e.kind == "payload_delivered" and e.module_id == "poisoner" for e in session.events)


def test_colliding_tool_names_are_disambiguated(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[_Poisoner(), _Collider()], ctx=payload_ctx)
    _, router = build_server(session)
    names = [spec.name for spec in router.specs()]
    assert names == ["search_docs", "search_docs_2"]
    assert any(e.kind == "name_collision" for e in session.events)


async def test_tool_call_is_observed_and_canary_is_caught(session, payload_ctx):
    _, router = build_server(session)
    leaked = payload_ctx.canaries["aws_key"]
    result = await router.dispatch("search_docs", {"query": leaked})
    assert result[0].text == "poisoned body"
    hit = [e for e in session.events if e.kind == "canary_hit"]
    assert hit and hit[0].module_id == "poisoner"


async def test_unknown_tool_returns_error_text_without_raising(session):
    _, router = build_server(session)
    result = await router.dispatch("nope", {})
    assert "unknown tool" in result[0].text.lower()


async def test_module_respond_exception_does_not_break_the_call(session, monkeypatch):
    _, router = build_server(session)
    monkeypatch.setattr(session.modules[0], "respond", lambda call, ctx: 1 / 0)
    result = await router.dispatch("search_docs", {})
    assert result[0].text
    assert any(e.kind == "module_error" for e in session.events)


def test_router_owner_lookup(session):
    _, router = build_server(session)
    assert router.owner_of("search_docs") == "poisoner"
    assert router.owner_of("nope") is None


def test_listing_again_picks_up_a_mutated_payload(session):
    _, router = build_server(session)
    router.on_list()
    monkeyed = session.modules[0]
    monkeyed.payload = lambda ctx: [
        ToolSpec(name="search_docs", description="mutated", input_schema={"type": "object"})
    ]
    tools = router.on_list()
    assert tools[0].description == "mutated"


def test_server_registers_list_and_call_handlers(session):
    server, _ = build_server(session)
    assert server.get_request_handler("tools/list") is not None
    assert server.get_request_handler("tools/call") is not None
