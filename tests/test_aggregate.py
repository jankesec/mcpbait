from mcpwn.aggregate import aggregate, render_aggregate, worst_case_score
from mcpwn.engine import Session
from mcpwn.types import Verdict


def _session(tmp_path, payload_ctx, verdicts, name):
    session = Session(tmp_path / name, modules=[], ctx=payload_ctx)
    session._verdict_cache = verdicts
    return session


def test_worst_verdict_wins_across_runs(tmp_path, payload_ctx):
    lucky = _session(tmp_path, payload_ctx, {"a": Verdict.IGNORED}, "1")
    unlucky = _session(tmp_path, payload_ctx, {"a": Verdict.COMPROMISED}, "2")
    summary = aggregate([lucky, unlucky])
    assert summary["modules"]["a"]["worst"] == "COMPROMISED"
    assert summary["modules"]["a"]["compromised"] == 1
    assert summary["modules"]["a"]["runs"] == 2


def test_flags_inconsistency_between_runs(tmp_path, payload_ctx):
    a = _session(tmp_path, payload_ctx, {"m": Verdict.BLOCKED}, "1")
    b = _session(tmp_path, payload_ctx, {"m": Verdict.COMPROMISED}, "2")
    summary = aggregate([a, b])
    assert summary["consistent"] is False
    assert summary["worst_score"] == 0.0
    assert summary["mean_score"] == 5.0


def test_reports_consistency_when_every_run_agrees(tmp_path, payload_ctx):
    runs = [_session(tmp_path, payload_ctx, {"m": Verdict.IGNORED}, str(i)) for i in range(3)]
    summary = aggregate(runs)
    assert summary["consistent"] is True
    assert summary["modules"]["m"]["counts"] == {"IGNORED": 3}


def test_worst_case_score_is_not_the_mean(tmp_path, payload_ctx):
    """A technique that landed once has landed, however many times it did not."""
    a = _session(tmp_path, payload_ctx, {"x": Verdict.BLOCKED, "y": Verdict.BLOCKED}, "1")
    b = _session(tmp_path, payload_ctx, {"x": Verdict.COMPROMISED, "y": Verdict.BLOCKED}, "2")
    summary = aggregate([a, b])
    assert summary["mean_score"] == 7.5
    assert worst_case_score(summary) == 5.0


def test_not_run_modules_are_excluded_from_the_worst_case_score(tmp_path, payload_ctx):
    only = _session(tmp_path, payload_ctx, {"x": Verdict.BLOCKED, "y": Verdict.NOT_RUN}, "1")
    assert worst_case_score(aggregate([only])) == 10.0


def test_table_orders_by_severity(tmp_path, payload_ctx):
    from rich.console import Console

    session = _session(
        tmp_path,
        payload_ctx,
        {"safe": Verdict.BLOCKED, "bad": Verdict.COMPROMISED, "mid": Verdict.BAITED},
        "1",
    )
    with (tmp_path / "out.txt").open("w") as handle:
        Console(file=handle, width=110).print(render_aggregate(aggregate([session])))
    lines = (tmp_path / "out.txt").read_text().splitlines()
    order = [i for i, line in enumerate(lines) if any(k in line for k in ("bad", "mid", "safe"))]
    assert order == sorted(order)
    body = "\n".join(lines)
    assert body.index("bad") < body.index("mid") < body.index("safe")
