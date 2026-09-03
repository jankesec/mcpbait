from mcpbait.engine import Session
from mcpbait.sarif import to_sarif
from mcpbait.types import Verdict


def test_to_sarif_structure(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session.record("canary_hit", "tool_poisoning", {"canary": "aws_key", "encoding": "raw"})
    session._verdict_cache = {"tool_poisoning": Verdict.COMPROMISED}

    sarif = to_sarif(session)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpbait"
    assert len(run["tool"]["driver"]["rules"]) > 0

    # Results must reflect compromised module
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "tool_poisoning"
    assert result["level"] == "error"
    assert result["properties"]["verdict"] == "COMPROMISED"


def test_to_sarif_empty_when_all_safe(tmp_path, payload_ctx):
    session = Session(tmp_path, modules=[], ctx=payload_ctx)
    session._verdict_cache = {"tool_poisoning": Verdict.BLOCKED}

    sarif = to_sarif(session)
    assert len(sarif["runs"][0]["results"]) == 0
