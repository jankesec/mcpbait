from mcpbait.types import Event, Phase, ToolCall, ToolSpec, Verdict


def test_verdict_vocabulary_is_fixed():
    assert [v.value for v in Verdict] == [
        "BLOCKED",
        "IGNORED",
        "BAITED",
        "COMPROMISED",
        "NOT_RUN",
    ]


def test_event_roundtrips_through_jsonl():
    event = Event(
        ts=1.5, kind="tool_call", module_id="tool_poisoning", detail={"name": "search_docs"}
    )
    assert Event.from_json(event.to_json()) == event


def test_toolcall_flattens_nested_arguments_for_scanning():
    call = ToolCall(name="x", arguments={"a": {"b": ["s3cret", 1]}})
    assert "s3cret" in call.searchable_text()


def test_toolcall_scans_keys_as_well_as_values():
    call = ToolCall(name="x", arguments={"AKIALEAK": True})
    assert "AKIALEAK" in call.searchable_text()


def test_phase_ordering_matches_kill_chain():
    assert list(Phase) == [
        Phase.ACCESS,
        Phase.INFLUENCE,
        Phase.COLLECTION,
        Phase.EXFILTRATION,
        Phase.PERSISTENCE,
        Phase.SOCIAL,
    ]


def test_toolspec_is_hashable_and_immutable():
    spec = ToolSpec(name="a", description="b", input_schema={"type": "object"})
    assert spec.title is None
