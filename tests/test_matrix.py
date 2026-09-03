from rich.console import Console

from mcpbait.matrix import render_matrix_markdown, render_matrix_table
from mcpbait.types import Verdict


def test_render_matrix_markdown():
    matrix_data = {
        "models": {
            "gpt-4o": {
                "worst_case_score": 8.5,
                "mean_score": 9.0,
                "modules": {
                    "tool_poisoning": {"worst": str(Verdict.BLOCKED)},
                    "rug_pull": {"worst": str(Verdict.BLOCKED)},
                },
            },
            "claude-3-5-sonnet": {
                "worst_case_score": 5.0,
                "mean_score": 6.5,
                "modules": {
                    "tool_poisoning": {"worst": str(Verdict.COMPROMISED)},
                    "rug_pull": {"worst": str(Verdict.BAITED)},
                },
            },
        }
    }

    markdown = render_matrix_markdown(matrix_data)
    assert "# 🛡️ MCP Security Leaderboard" in markdown
    assert "gpt-4o" in markdown
    assert "claude-3-5-sonnet" in markdown
    assert "8.5 / 10" in markdown
    assert "Hardened" in markdown or "Resilient" in markdown


def test_render_matrix_table(tmp_path):
    matrix_data = {
        "models": {
            "model-a": {
                "worst_case_score": 10.0,
                "mean_score": 10.0,
                "modules": {"tool_poisoning": {"worst": str(Verdict.BLOCKED)}},
            },
            "model-b": {
                "worst_case_score": 2.0,
                "mean_score": 3.0,
                "modules": {"tool_poisoning": {"worst": str(Verdict.COMPROMISED)}},
            },
        }
    }

    table = render_matrix_table(matrix_data)
    with (tmp_path / "out.txt").open("w") as handle:
        console = Console(file=handle, width=120)
        console.print(table)
    output = (tmp_path / "out.txt").read_text()
    assert "model-a" in output
    assert "model-b" in output
    assert "A+ (Hardened)" in output
    assert "F (Critical)" in output
