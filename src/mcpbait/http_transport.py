"""Streamable HTTP transport.

stdio reaches an agent that runs mcpbait as a subprocess. A remote or hosted agent
connects over HTTP instead, and that transport is not merely a second way in: it
carries request headers, a session identifier and a long-lived stream, none of which
exist over stdio. Techniques that live on that surface read the evidence recorded
here through the ordinary event log, so they stay as pure as every other module.

Nothing is written to stdout: `serve --http` may still be launched by a supervisor
that treats stdout as structured output.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings

from mcpbait.engine import Session
from mcpbait.server import build_server
from mcpbait.types import redact

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8731
DEFAULT_PATH = "/mcp"

#: Headers worth recording as evidence. A client that forwards any of these to an
#: arbitrary remote MCP server has leaked something, and the leak is a fact rather
#: than an inference. Values are redacted before they reach the log.
WATCHED_HEADERS = (
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "openai-api-key",
    "anthropic-api-key",
)

#: Headers recorded in full because they carry no secret and decide whether the
#: client is doing origin validation at all.
CONTEXT_HEADERS = ("origin", "host", "referer", "user-agent", "mcp-session-id")


def observe_request(session: Session, scope: dict[str, Any]) -> None:
    """Record one inbound HTTP request as evidence.

    Secret-bearing headers are redacted; context headers are kept whole because a
    missing Origin is exactly as interesting as a present one.
    """
    raw = scope.get("headers") or []
    headers: dict[str, str] = {}
    for key, value in raw:
        name = key.decode("latin-1").lower()
        if name in WATCHED_HEADERS:
            headers[name] = redact(value.decode("latin-1"))
        elif name in CONTEXT_HEADERS:
            headers[name] = value.decode("latin-1")
    session.record(
        "http_request",
        "",
        {
            "method": scope.get("method", ""),
            "path": scope.get("path", ""),
            "headers": headers,
            "missing": [h for h in CONTEXT_HEADERS if h not in headers],
        },
    )


class AdversarialHttpApp:
    """The adversarial MCP server as an ASGI application.

    Written as a plain ASGI callable rather than mounted in a routing framework: a
    mount would answer the endpoint path with a redirect to its trailing-slash form,
    and the session manager's lifetime would be tied to a lifespan protocol that a
    test client does not run. `run()` makes that lifetime explicit, so the same code
    path serves uvicorn and the test suite.
    """

    def __init__(
        self,
        session: Session,
        *,
        path: str = DEFAULT_PATH,
        allowed_hosts: list[str] | None = None,
        allowed_origins: list[str] | None = None,
    ) -> None:
        self.session = session
        self.path = path
        server, _ = build_server(session)
        # DNS rebinding protection stays on. mcpbait exists to prove an agent can be
        # hijacked by a server; leaving its own server open to a hostile web page
        # would hand that same capability to anyone who can reach this port.
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts or [f"{DEFAULT_HOST}:{DEFAULT_PORT}", DEFAULT_HOST],
            allowed_origins=allowed_origins or [],
        )
        self._manager = StreamableHTTPSessionManager(app=server, security_settings=security)

    @contextlib.asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """Hold the session manager open for the lifetime of the server."""
        async with self._manager.run():
            yield

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        if scope.get("path") != self.path:
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return
        observe_request(self.session, scope)
        await self._manager.handle_request(scope, receive, send)


async def run_http(
    session: Session,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    path: str = DEFAULT_PATH,
) -> None:
    """Serve over Streamable HTTP until interrupted."""
    import uvicorn

    app = AdversarialHttpApp(session, path=path, allowed_hosts=[f"{host}:{port}", host])
    config = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
    async with app.run():
        await uvicorn.Server(config).serve()
