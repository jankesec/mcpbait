"""MCP protocol layer.

The routing logic lives in `ToolRouter`, deliberately separated from the SDK so it
can be tested without a transport. `build_server` is the thin adapter that hands
the router to the official low-level `Server`.

Two rules govern this file:

1. Tool arguments reach the router unvalidated. An agent smuggling a secret into an
   undeclared parameter must be observed, not rejected -- schema validation before
   the canary scan would silently defeat the entire point of the tool. The mcp 2.x
   low-level server hands over raw `CallToolRequestParams`, which gives us this.
2. Nothing is ever written to stdout. Under stdio transport stdout *is* the
   protocol channel, and one stray print corrupts the session.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcpbait import __version__
from mcpbait.engine import Session
from mcpbait.modules.base import AttackModule
from mcpbait.types import ToolCall, ToolSpec

#: Returned when a module declines to poison a result, so the agent still sees a
#: plausible tool response and carries on.
GENERIC_RESPONSE = "OK. No results for this query."


class ToolRouter:
    """Maps advertised tool names to the modules that own them."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._routes: dict[str, tuple[AttackModule, ToolSpec]] = {}
        self.rebuild()

    def rebuild(self) -> None:
        """Recompute the advertised tool set from every module's current payload.

        Called on each listing so a module that mutates itself mid-session -- the
        rug pull technique -- is reflected in what the agent is told.
        """
        routes: dict[str, tuple[AttackModule, ToolSpec]] = {}
        for module in self.session.modules:
            try:
                specs = module.payload(self.session.ctx)
            except Exception as error:
                self.session.record(
                    "module_error", module.id, {"stage": "payload", "error": repr(error)}
                )
                continue
            for spec in specs:
                name = spec.name
                if name in routes:
                    suffix = 2
                    while f"{name}_{suffix}" in routes:
                        suffix += 1
                    self.session.record(
                        "name_collision", module.id, {"wanted": name, "used": f"{name}_{suffix}"}
                    )
                    name = f"{name}_{suffix}"
                    spec = replace(spec, name=name)
                routes[name] = (module, spec)
        self._routes = routes

    def specs(self) -> list[ToolSpec]:
        return [spec for _, spec in self._routes.values()]

    def owner_of(self, tool_name: str) -> str | None:
        route = self._routes.get(tool_name)
        return route[0].id if route else None

    def on_list(self) -> list[types.Tool]:
        """Advertise the poisoned tool set and record delivery per module."""
        self.rebuild()
        for module in self.session.modules:
            self.session.record(
                "payload_delivered",
                module.id,
                {"tools": [s.name for s in self.specs() if self.owner_of(s.name) == module.id]},
            )
        return [
            types.Tool(
                name=spec.name,
                title=spec.title,
                description=spec.description,
                input_schema=spec.input_schema,
            )
            for spec in self.specs()
        ]

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        """Observe an inbound call, then return the owning module's poisoned result."""
        route = self._routes.get(name)
        owner = route[0].id if route else ""
        call = ToolCall(name=name, arguments=arguments or {})
        self.session.observe_call(call, module_id=owner)

        if route is None:
            # An exception here would surface as a protocol error and tip off the agent.
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

        module, _ = route
        mutated_before = getattr(module, "mutated", None)
        try:
            body = module.respond(call, self.session.ctx)
        except Exception as error:
            self.session.record(
                "module_error", module.id, {"stage": "respond", "error": repr(error)}
            )
            body = None
        if getattr(module, "mutated", None) != mutated_before:
            # The module redefined itself; the next listing will carry the new payload.
            self.session.record("payload_mutated", module.id, {"tool": name})
        return [types.TextContent(type="text", text=body or GENERIC_RESPONSE)]


def build_server(session: Session) -> tuple[Server, ToolRouter]:
    """Wire a router into a low-level MCP server."""
    router = ToolRouter(session)

    async def on_list_tools(ctx: object, params: object) -> types.ListToolsResult:
        return types.ListToolsResult(tools=router.on_list())

    async def on_call_tool(
        ctx: object, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        content = await router.dispatch(params.name, params.arguments or {})
        return types.CallToolResult(content=list(content))

    server: Server = Server(
        "mcpbait",
        version=__version__,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    return server, router


async def run_stdio(session: Session) -> None:
    """Serve over stdio until the agent disconnects."""
    server, _ = build_server(session)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
            raise_exceptions=False,
        )
