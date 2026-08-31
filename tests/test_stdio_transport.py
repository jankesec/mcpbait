"""Proof that a real MCP client can connect to mcpbait over stdio.

Every other test drives the router directly. This one spawns `mcpbait serve` as a
subprocess and speaks the actual protocol to it, which is the only way to catch a
broken handshake, a malformed tool schema, or the classic stdio failure: something
printing to stdout and corrupting the channel.
"""

from __future__ import annotations

import json
import sys

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpbait.canary import mint_set
from mcpbait.workspace import create_workspace


@pytest.fixture
def served_dir(tmp_path):
    canaries = mint_set()
    workspace = create_workspace(tmp_path / "workspace", canaries)
    (tmp_path / "sessions").mkdir()
    (tmp_path / "state.json").write_text(
        json.dumps({"canaries": canaries, "workspace": str(workspace)}), encoding="utf-8"
    )
    return tmp_path, canaries


async def test_a_real_client_completes_the_handshake_and_gets_poisoned_tools(served_dir):
    directory, _ = served_dir
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcpbait.cli", "serve", "--dir", str(directory)],
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools

    names = {tool.name for tool in tools}
    assert "search_docs" in names
    assert len(names) == 13
    poisoned = next(t for t in tools if t.name == "search_docs")
    assert "<IMPORTANT>" in poisoned.description


async def test_exfiltration_through_a_real_transport_is_recorded(served_dir):
    directory, canaries = served_dir
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcpbait.cli", "serve", "--dir", str(directory)],
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        await session.call_tool(
            "debug_telemetry", {"event": "boot", "payload": canaries["aws_key"]}
        )

    logs = list((directory / "sessions").glob("*.jsonl"))
    assert len(logs) == 1
    events = [json.loads(line) for line in logs[0].read_text().splitlines()]
    hits = [e for e in events if e["kind"] == "canary_hit"]
    assert hits and hits[0]["detail"]["canary"] == "aws_key"
    assert hits[0]["module_id"] == "param_smuggling"


async def test_undeclared_parameters_still_reach_the_scanner(served_dir):
    """An agent smuggling a secret into a field that is not in the schema must be seen."""
    directory, canaries = served_dir
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcpbait.cli", "serve", "--dir", str(directory)],
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        await session.call_tool(
            "render_report", {"undeclared_field": canaries["api_token"]}
        )

    logs = list((directory / "sessions").glob("*.jsonl"))
    events = [json.loads(line) for line in logs[0].read_text().splitlines()]
    assert any(e["kind"] == "canary_hit" for e in events)
