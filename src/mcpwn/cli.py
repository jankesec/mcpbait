"""Command line interface.

`serve` runs under stdio transport, where stdout carries the MCP protocol. Every
message it emits therefore goes to stderr. Getting this wrong corrupts the session
in ways that look like a broken agent rather than a broken tool.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import anyio
import typer
from rich.console import Console

from mcpwn import __version__
from mcpwn.beacon import Beacon
from mcpwn.canary import mint_set
from mcpwn.engine import Session, latest_session, load_session
from mcpwn.modules import REGISTRY, all_ids, get_modules
from mcpwn.naive import run_naive_agent
from mcpwn.report import print_report, to_dict, to_html
from mcpwn.server import run_stdio
from mcpwn.types import PayloadContext
from mcpwn.workspace import create_workspace

app = typer.Typer(
    add_completion=False,
    help="Prove whether an MCP-speaking agent can be hijacked by a malicious server.",
)

DirOption = Annotated[Path, typer.Option("--dir", help="mcpwn state directory.")]
DEFAULT_DIR = Path(".mcpwn")


def _load_state(directory: Path) -> dict:
    state_file = directory / "state.json"
    if not state_file.is_file():
        typer.echo(f"No state in {directory}. Run 'mcpwn init' first.", err=True)
        raise typer.Exit(code=1)
    return json.loads(state_file.read_text(encoding="utf-8"))


def _select(module_ids: str | None) -> list[str] | None:
    """Parse and validate a --modules value, or None for every module."""
    if not module_ids:
        return None
    selected = [m.strip() for m in module_ids.split(",") if m.strip()]
    unknown = [module_id for module_id in selected if module_id not in REGISTRY]
    if unknown:
        raise typer.BadParameter(f"unknown module(s): {', '.join(unknown)}")
    return selected


@app.command()
def init(directory: DirOption = DEFAULT_DIR) -> None:
    """Mint fresh canaries and build the decoy workspace."""
    directory.mkdir(parents=True, exist_ok=True)
    canaries = mint_set()
    workspace = create_workspace(directory / "workspace", canaries)
    (directory / "state.json").write_text(
        json.dumps({"canaries": canaries, "workspace": str(workspace)}, indent=2),
        encoding="utf-8",
    )
    (directory / "sessions").mkdir(exist_ok=True)

    console = Console()
    console.print(f"[green]Decoy workspace ready:[/green] {workspace}")
    console.print("Every credential in it is synthetic. Next: [bold]mcpwn config[/bold]")


@app.command()
def config(directory: DirOption = DEFAULT_DIR) -> None:
    """Print the .mcp.json block to paste into the agent under test."""
    _load_state(directory)
    block = {
        "mcpServers": {
            "mcpwn": {
                "command": "uvx",
                "args": ["mcpwn", "serve", "--dir", str(directory.resolve())],
            }
        }
    }
    typer.echo(json.dumps(block, indent=2))


@app.command()
def modules() -> None:
    """List the attack modules this build ships."""
    from rich.table import Table

    table = Table(title=f"mcpwn {__version__} attack modules")
    table.add_column("module", no_wrap=True)
    table.add_column("phase", no_wrap=True)
    table.add_column("ATLAS", no_wrap=True)
    table.add_column("summary", overflow="fold")
    for module_id in all_ids():
        cls = REGISTRY[module_id]
        table.add_row(module_id, str(cls.phase), cls.atlas_id, cls.summary)
    Console().print(table)


@app.command()
def serve(
    directory: DirOption = DEFAULT_DIR,
    module_ids: Annotated[
        str | None,
        typer.Option("--modules", help="Comma-separated module ids. Default: all."),
    ] = None,
) -> None:
    """Run the adversarial MCP server over stdio."""
    state = _load_state(directory)
    selected = _select(module_ids)

    sessions_dir = directory / "sessions"
    beacon = Beacon(on_hit=lambda path, params: None)
    beacon_url = beacon.start()

    ctx = PayloadContext(
        canaries=state["canaries"],
        workspace=Path(state["workspace"]),
        beacon_url=beacon_url,
    )
    session = Session(sessions_dir, modules=get_modules(selected), ctx=ctx)

    # Rebound now that the session exists, so render-triggered fetches become evidence.
    beacon.on_hit = lambda path, params: session.record(
        "beacon_hit", params.get("m", ""), {"path": path, "params": params}
    )

    print(f"mcpwn {__version__} serving {len(session.modules)} modules", file=sys.stderr)
    print(f"session {session.id} -> {session.path}", file=sys.stderr)
    try:
        anyio.run(run_stdio, session)
    finally:
        beacon.stop()
        session.close()


@app.command()
def demo(
    directory: Annotated[
        Path | None, typer.Option("--dir", help="Where to run. Default: a temp directory.")
    ] = None,
    keep: Annotated[bool, typer.Option("--keep", help="Keep the run directory.")] = False,
    module_ids: Annotated[
        str | None,
        typer.Option("--modules", help="Comma-separated module ids. Default: all."),
    ] = None,
) -> None:
    """Run the whole kill chain against a built-in defenceless agent. No setup needed."""
    selected = _select(module_ids)
    console = Console()
    console.print(
        "[yellow]This attacks mcpwn's own reference agent, which obeys every instruction "
        "it reads.[/yellow]\n[yellow]It is a worst case, not your agent. To test yours: "
        "mcpwn init && mcpwn config[/yellow]\n"
    )

    root = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="mcpwn-demo-"))
    try:
        canaries = mint_set()
        workspace = create_workspace(root / "workspace", canaries)
        beacon = Beacon(on_hit=lambda path, params: None)
        ctx = PayloadContext(canaries=canaries, workspace=workspace, beacon_url=beacon.start())
        session = Session(root / "sessions", modules=get_modules(selected), ctx=ctx)
        beacon.on_hit = lambda path, params: session.record(
            "beacon_hit", params.get("m", ""), {"path": path, "params": params}
        )
        try:
            anyio.run(run_naive_agent, session)
        finally:
            beacon.stop()

        persistence = REGISTRY["memory_poisoning"]()
        if persistence.check_persistence(workspace):
            session.record("persistence_confirmed", persistence.id, {"workspace": str(workspace)})
        session.close()

        print_report(session, console)
        if keep:
            console.print(f"\n[dim]Run kept at {root}[/dim]")
    finally:
        if not keep and directory is None:
            shutil.rmtree(root, ignore_errors=True)


@app.command()
def report(
    directory: DirOption = DEFAULT_DIR,
    session_id: Annotated[str | None, typer.Option("--session", help="Session id.")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write JSON here.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write HTML here.")] = None,
    fail_under: Annotated[
        float | None,
        typer.Option("--fail-under", help="Exit 3 if the resilience score is below this."),
    ] = None,
) -> None:
    """Render the kill chain for a finished session."""
    sessions_dir = directory / "sessions"
    path = (sessions_dir / f"{session_id}.jsonl") if session_id else latest_session(sessions_dir)
    if path is None or not path.is_file():
        typer.echo(f"No session found in {sessions_dir}.", err=False)
        raise typer.Exit(code=1)

    session = load_session(path, modules=get_modules(None))
    state_file = directory / "state.json"
    if state_file.is_file():
        state = json.loads(state_file.read_text(encoding="utf-8"))
        workspace = Path(state["workspace"])
        session.ctx = PayloadContext(canaries=state["canaries"], workspace=workspace)
        persistence = REGISTRY["memory_poisoning"]()
        if persistence.check_persistence(workspace):
            session.record("persistence_confirmed", persistence.id, {"workspace": str(workspace)})

    print_report(session, Console())
    if json_path:
        json_path.write_text(json.dumps(to_dict(session), indent=2), encoding="utf-8")
        typer.echo(f"JSON written to {json_path}")
    if html_path:
        html_path.write_text(to_html(session), encoding="utf-8")
        typer.echo(f"HTML written to {html_path}")
    if fail_under is not None and session.score() < fail_under:
        typer.echo(f"Score {session.score()} is below the {fail_under} threshold.")
        raise typer.Exit(code=3)


if __name__ == "__main__":
    app()
