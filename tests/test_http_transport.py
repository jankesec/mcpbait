"""HTTP transport tests.

Everything here talks to the ASGI application in-process through httpx's ASGI
transport, so the suite keeps its promise: no API key, no network, no model.
"""

from __future__ import annotations

import json

import httpx
import pytest

from mcpbait.engine import Session
from mcpbait.http_transport import DEFAULT_PATH, AdversarialHttpApp, observe_request
from mcpbait.modules import get_modules
from mcpbait.types import redact

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0"},
    },
}
ACCEPT = "application/json, text/event-stream"


@pytest.fixture
def http_session(tmp_path, payload_ctx):
    return Session(tmp_path, modules=get_modules(None), ctx=payload_ctx)


async def test_initialize_over_http_returns_a_session_id(http_session):
    app = AdversarialHttpApp(http_session)
    async with (
        app.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
        ) as client,
    ):
        response = await client.post(
            DEFAULT_PATH,
            json=INIT,
            headers={"Accept": ACCEPT, "Content-Type": "application/json"},
        )
    assert response.status_code == 200, response.text
    assert response.headers.get("mcp-session-id")


async def test_every_request_lands_in_the_evidence_log(http_session):
    app = AdversarialHttpApp(http_session)
    async with (
        app.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
        ) as client,
    ):
        await client.post(
            DEFAULT_PATH, json=INIT, headers={"Accept": ACCEPT, "Content-Type": "application/json"}
        )

    requests = [e for e in http_session.events if e.kind == "http_request"]
    assert requests
    assert requests[0].detail["method"] == "POST"
    assert requests[0].detail["path"] == DEFAULT_PATH


async def test_a_forwarded_credential_is_recorded_but_never_in_full(http_session):
    """The whole point of header_harvest -- and the reason the log must redact."""
    secret = "sk-live-abcdefghijklmnopqrstuvwxyz-0123456789"
    app = AdversarialHttpApp(http_session)
    async with (
        app.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
        ) as client,
    ):
        await client.post(
            DEFAULT_PATH,
            json=INIT,
            headers={
                "Accept": ACCEPT,
                "Content-Type": "application/json",
                "Authorization": f"Bearer {secret}",
            },
        )

    recorded = [e for e in http_session.events if e.kind == "http_request"]
    blob = json.dumps([e.detail for e in recorded])
    assert "authorization" in blob
    assert secret not in blob, "a harvested credential must never reach the log in full"


def test_observe_request_notes_a_missing_origin(http_session):
    """A client that sends no Origin is exactly as interesting as one that does."""
    observe_request(http_session, {"method": "POST", "path": "/mcp", "headers": []})
    detail = http_session.events[-1].detail
    assert "origin" in detail["missing"]


def test_observe_request_keeps_context_headers_whole(http_session):
    observe_request(
        http_session,
        {
            "method": "POST",
            "path": "/mcp",
            "headers": [(b"origin", b"https://evil.example"), (b"host", b"127.0.0.1:8731")],
        },
    )
    headers = http_session.events[-1].detail["headers"]
    assert headers["origin"] == "https://evil.example"
    assert headers["host"] == "127.0.0.1:8731"


@pytest.mark.parametrize(
    ("value", "expected_in"),
    [("", "0 chars"), ("short", "5 chars"), ("sk-abcdefghijklmnop", "sk-a...mnop")],
)
def test_redact_keeps_enough_to_recognise_and_not_enough_to_use(value, expected_in):
    assert expected_in in redact(value)


def test_redact_never_leaves_the_middle_of_a_long_secret():
    secret = "sk-live-THISISTHESECRETMIDDLE-9f2c"
    assert "THISISTHESECRETMIDDLE" not in redact(secret)
