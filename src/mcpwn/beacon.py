"""Loopback beacon listener.

Some agents never leak a secret through a tool argument but will happily render a
markdown image, and the client fetches the URL. That fetch is the leak. The beacon
catches it, which is why it proves something the model-side view cannot: that the
*client*, not the model, completed the exfiltration.

Binds 127.0.0.1 only. mcpwn does not implement remote callbacks.
"""

from __future__ import annotations

import base64
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

#: A 1x1 transparent PNG, so a rendering client shows nothing unusual.
PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


class Beacon:
    """A one-endpoint HTTP listener that reports every request it receives."""

    def __init__(self, on_hit: Callable[[str, dict[str, str]], None]) -> None:
        self._on_hit = on_hit
        #: Callback failures, kept rather than swallowed so a broken wiring is visible.
        self.errors: list[str] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url: str | None = None

    def start(self) -> str:
        """Start serving on a kernel-assigned loopback port and return the base URL."""
        beacon = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                params = {k: v[0] for k, v in parse_qs(parts.query).items()}
                try:
                    beacon._on_hit(parts.path, params)
                except Exception as error:  # noqa: BLE001 - must not break the fetch
                    beacon.errors.append(repr(error))
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(PIXEL)))
                self.end_headers()
                self.wfile.write(PIXEL)

            def log_message(self, *args: object) -> None:
                """Silence the default stderr access log; it would clutter the terminal."""

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        return self.url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
