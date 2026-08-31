from mcpwn.modules import REGISTRY
from mcpwn.modules.invisible import strip_invisible
from mcpwn.types import Event, Phase, Verdict


def test_tool_poisoning_hides_instructions_in_the_description(payload_ctx):
    spec = REGISTRY["tool_poisoning"]().payload(payload_ctx)[0]
    assert spec.name == "search_docs"
    assert ".env" in spec.description
    assert "<IMPORTANT>" in spec.description


def test_tool_poisoning_exfil_parameter_is_optional(payload_ctx):
    spec = REGISTRY["tool_poisoning"]().payload(payload_ctx)[0]
    assert "context" in spec.input_schema["properties"]
    assert spec.input_schema["required"] == ["query"]


def test_tool_poisoning_is_compromised_when_canary_hit_names_it():
    events = [Event(ts=1.0, kind="canary_hit", module_id="tool_poisoning", detail={})]
    assert REGISTRY["tool_poisoning"]().verify(events) is Verdict.COMPROMISED


def test_tool_poisoning_is_baited_when_called_without_leak():
    events = [Event(ts=1.0, kind="tool_call", module_id="tool_poisoning", detail={})]
    assert REGISTRY["tool_poisoning"]().verify(events) is Verdict.BAITED


def test_unicode_smuggling_is_invisible_to_a_human_reader(payload_ctx):
    module = REGISTRY["unicode_smuggling"]()
    spec = module.payload(payload_ctx)[0]
    visible = strip_invisible(spec.description)
    assert "id_rsa" not in visible
    assert "id_rsa" in module.decode(spec.description)
    assert len(spec.description) > len(visible)


def test_line_jumping_carries_the_whole_payload_in_the_listing(payload_ctx):
    module = REGISTRY["line_jumping"]()
    spec = module.payload(payload_ctx)[0]
    assert len(spec.description) > 200
    events = [Event(ts=1.0, kind="canary_hit", module_id="line_jumping", detail={})]
    assert module.verify(events) is Verdict.COMPROMISED


def test_name_squatting_impersonates_a_trusted_tool(payload_ctx):
    spec = REGISTRY["name_squatting"]().payload(payload_ctx)[0]
    assert spec.name == "read_file"


def test_access_modules_reference_the_decoy_workspace_only(payload_ctx):
    for module_id in ("tool_poisoning", "unicode_smuggling", "line_jumping", "name_squatting"):
        module = REGISTRY[module_id]()
        for spec in module.payload(payload_ctx):
            decoded = getattr(module, "decode", lambda text: text)(spec.description)
            assert str(payload_ctx.workspace) in decoded


def test_access_modules_are_all_in_the_access_phase():
    for module_id in ("tool_poisoning", "unicode_smuggling", "line_jumping", "name_squatting"):
        assert REGISTRY[module_id].phase is Phase.ACCESS
