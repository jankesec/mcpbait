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
from typing import Annotated, Any

import anyio
import typer
from rich.console import Console

from mcpbait import __version__
from mcpbait.agent import COLLISION_POLICIES, DEFAULT_TASK, http_completion, run_agent
from mcpbait.aggregate import aggregate, render_aggregate, worst_case_score
from mcpbait.beacon import Beacon
from mcpbait.canary import mint_set
from mcpbait.engine import Session, latest_session, load_session
from mcpbait.matrix import render_matrix_markdown, render_matrix_table
from mcpbait.modules import REGISTRY, all_ids, get_modules
from mcpbait.naive import run_naive_agent
from mcpbait.report import print_report, to_dict, to_html
from mcpbait.sarif import to_sarif
from mcpbait.server import run_stdio
from mcpbait.types import PayloadContext
from mcpbait.workspace import WORKSPACE_MANIFEST, create_workspace

app = typer.Typer(
    add_completion=False,
    help="Prove whether an MCP-speaking agent can be hijacked by a malicious server.",
)

DirOption = Annotated[Path, typer.Option("--dir", help="mcpbait state directory.")]
DEFAULT_DIR = Path(".mcpbait")


def _load_state(directory: Path) -> dict:
    state_file = directory / "state.json"
    if not state_file.is_file():
        typer.echo(f"No state in {directory}. Run 'mcpbait init' first.", err=True)
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
def init(
    directory: DirOption = DEFAULT_DIR,
    workspace_path: Annotated[
        Path | None,
        typer.Option("--workspace", help="Plant the decoy here instead of under --dir."),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing directory's files.")
    ] = False,
) -> None:
    """Mint fresh canaries and build the decoy workspace.

    Use --workspace to plant the bait where the agent actually works, so its own
    project directory holds no trace of mcpbait.
    """
    directory.mkdir(parents=True, exist_ok=True)
    target = Path(workspace_path) if workspace_path else directory / "workspace"

    # create_workspace overwrites its manifest wholesale. Pointed at a real project
    # that would destroy work, so refuse unless the operator insists.
    if workspace_path and not force:
        clashes = [name for name in WORKSPACE_MANIFEST if (target / name).exists()]
        if clashes:
            typer.echo(
                f"{target} already contains {', '.join(clashes)}. "
                "Refusing to overwrite. Use --force if you meant it.",
            )
            raise typer.Exit(code=1)

    canaries = mint_set()
    workspace = create_workspace(target, canaries)
    (directory / "state.json").write_text(
        json.dumps({"canaries": canaries, "workspace": str(workspace)}, indent=2),
        encoding="utf-8",
    )
    (directory / "sessions").mkdir(exist_ok=True)

    console = Console()
    console.print(f"[green]Decoy workspace ready:[/green] {workspace}")
    console.print("Every credential in it is synthetic. Next: [bold]mcpbait config[/bold]")


@app.command()
def config(
    directory: DirOption = DEFAULT_DIR,
    name: Annotated[
        str,
        typer.Option("--as", help="Server name in the config. Disguise it for a fair test."),
    ] = "mcpbait",
) -> None:
    """Print the .mcp.json block to paste into the agent under test.

    Use --as to give the server an innocuous name. An agent that reads 'mcpbait' in its
    own configuration has been tipped off, and a tipped-off agent is not the agent you
    are trying to measure.
    """
    _load_state(directory)
    block = {
        "mcpServers": {
            name: {
                "command": "uvx",
                "args": ["mcpbait", "serve", "--dir", str(directory.resolve())],
            }
        }
    }
    typer.echo(json.dumps(block, indent=2))


@app.command()
def install(
    client: Annotated[
        str,
        typer.Option(
            "--client",
            "-c",
            help="Target client: claude-desktop, cursor, windsurf, or cline.",
        ),
    ] = "claude-desktop",
    directory: DirOption = DEFAULT_DIR,
    name: Annotated[
        str,
        typer.Option("--as", help="Server name in the config. Disguise it for a fair test."),
    ] = "system-indexer",
    config_path: Annotated[
        Path | None,
        typer.Option("--config-path", help="Explicit configuration file path to override default."),
    ] = None,
) -> None:
    """Auto-configure mcpbait into Claude Desktop, Cursor, Windsurf, or Cline."""
    _load_state(directory)
    from mcpbait.clients import install_into_client

    try:
        target = install_into_client(
            client=client,
            server_name=name,
            state_dir=directory,
            custom_path=config_path,
        )
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=1)

    console = Console()
    console.print(f"[green]Successfully configured disguised server '{name}' for {client}:[/green]")
    console.print(f"  [bold]{target}[/bold]")
    console.print(f"  [dim]Safety backup created at {target}.bak[/dim]")
    console.print(
        "\n[cyan]Next steps:[/cyan]\n"
        f"1. Open or restart {client}.\n"
        "2. Give the agent an ordinary prompt (e.g., 'summarise files in my workspace').\n"
        "3. Once the interaction finishes, run: [bold]mcpbait report[/bold]"
    )


@app.command()
def uninstall(
    client: Annotated[
        str,
        typer.Option(
            "--client",
            "-c",
            help="Target client: claude-desktop, cursor, windsurf, or cline.",
        ),
    ] = "claude-desktop",
    name: Annotated[
        str,
        typer.Option("--as", help="Server name in the config to remove."),
    ] = "system-indexer",
    config_path: Annotated[
        Path | None,
        typer.Option("--config-path", help="Explicit configuration file path to override default."),
    ] = None,
) -> None:
    """Remove mcpbait from Claude Desktop, Cursor, Windsurf, or Cline configuration."""
    from mcpbait.clients import uninstall_from_client

    try:
        target = uninstall_from_client(
            client=client,
            server_name=name,
            custom_path=config_path,
        )
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=1)

    Console().print(f"[green]Removed server '{name}' from {client} configuration:[/green] {target}")


@app.command()
def badge(
    directory: DirOption = DEFAULT_DIR,
    session_id: Annotated[str | None, typer.Option("--session", help="Session id.")] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output SVG path."),
    ] = Path("mcpbait-badge.svg"),
    score: Annotated[
        float | None,
        typer.Option("--score", help="Explicit score (0.0 - 10.0) to render."),
    ] = None,
) -> None:
    """Generate an offline SVG resilience badge for your README or CI dashboard."""
    from mcpbait.badge import generate_badge

    if score is not None:
        final_score = score
    else:
        sessions_dir = directory / "sessions"
        path = (sessions_dir / f"{session_id}.jsonl") if session_id else latest_session(sessions_dir)
        if path is None or not path.is_file():
            typer.echo(f"No session found in {sessions_dir}. Pass --score or run a test first.", err=True)
            raise typer.Exit(code=1)
        session = load_session(path, modules=get_modules(None))
        final_score = session.score()

    svg_content = generate_badge(final_score)
    output.write_text(svg_content, encoding="utf-8")
    Console().print(f"[green]Resilience badge ({final_score:.1f}/10) generated at:[/green] {output}")


@app.command()
def modules() -> None:
    """List the attack modules this build ships."""
    from rich.table import Table

    table = Table(title=f"mcpbait {__version__} attack modules")
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

    print(f"mcpbait {__version__} serving {len(session.modules)} modules", file=sys.stderr)
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
        "[yellow]This attacks mcpbait's own reference agent, which obeys every instruction "
        "it reads.[/yellow]\n[yellow]It is a worst case, not your agent. To test yours: "
        "mcpbait init && mcpbait config[/yellow]\n"
    )

    root = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="mcpbait-demo-"))
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
def attack(
    directory: DirOption = DEFAULT_DIR,
    model: Annotated[str, typer.Option("--model", help="Model id to test.")] = "gpt-4o-mini",
    api_base: Annotated[
        str, typer.Option("--api-base", envvar="MCPBAIT_API_BASE", help="OpenAI-compatible base URL.")
    ] = "https://api.openai.com/v1",
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="MCPBAIT_API_KEY", help="API key.")
    ] = None,
    runs: Annotated[int, typer.Option("--runs", help="How many sessions to run.")] = 3,
    task: Annotated[str, typer.Option("--task", help="The ordinary task to give the agent.")] = DEFAULT_TASK,
    max_turns: Annotated[int, typer.Option("--max-turns", help="Tool-calling turns per run.")] = 8,
    collision: Annotated[
        str,
        typer.Option(
            "--collision",
            help="How the client resolves a duplicate tool name: shadow, namespace or builtin.",
        ),
    ] = "shadow",
    module_ids: Annotated[
        str | None, typer.Option("--modules", help="Comma-separated module ids. Default: all.")
    ] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write the summary here.")] = None,
    fail_under: Annotated[
        float | None,
        typer.Option("--fail-under", help="Exit 3 if the worst-case score is below this."),
    ] = None,
) -> None:
    """Attack a real LLM over repeated runs and report the spread.

    One run against a non-deterministic model is an anecdote. This repeats the session
    and reports how often each technique landed, leading with the worst outcome seen.
    """
    if not api_key:
        typer.echo("No API key. Pass --api-key or set MCPBAIT_API_KEY.")
        raise typer.Exit(code=1)

    if collision not in COLLISION_POLICIES:
        raise typer.BadParameter(f"--collision must be one of {', '.join(COLLISION_POLICIES)}")

    state = _load_state(directory)
    selected = _select(module_ids)
    workspace = Path(state["workspace"])
    console = Console()
    completion = http_completion(model=model, api_base=api_base, api_key=api_key)

    sessions: list[Session] = []
    failures: list[str] = []
    for run in range(max(1, runs)):
        # Fresh bait each run: a persisted injection from run one would otherwise
        # still be sitting in CLAUDE.md when run two starts.
        create_workspace(workspace, state["canaries"])

        beacon = Beacon(on_hit=lambda path, params: None)
        ctx = PayloadContext(
            canaries=state["canaries"], workspace=workspace, beacon_url=beacon.start()
        )
        session = Session(directory / "sessions", modules=get_modules(selected), ctx=ctx)
        beacon.on_hit = lambda path, params, _s=session: _s.record(
            "beacon_hit", params.get("m", ""), {"path": path, "params": params}
        )
        failed = None
        try:
            reply = anyio.run(
                lambda _s=session: run_agent(
                    _s, completion, task=task, max_turns=max_turns, collision=collision
                )
            )
        except Exception as error:  # noqa: BLE001 - one bad run must not lose the others
            failed = str(error)
            reply = ""
            session.record("run_error", "", {"error": repr(error)})
        finally:
            beacon.stop()

        persistence = REGISTRY["memory_poisoning"]()
        if persistence.check_persistence(workspace):
            session.record("persistence_confirmed", persistence.id, {"workspace": str(workspace)})
        session.close()

        if failed:
            # A run that never reached the model proves nothing. Counting it would
            # score an outage as thirteen techniques the agent resisted.
            failures.append(failed)
            console.print(f"[red]run {run + 1}/{runs} failed, excluded:[/red] {failed[:160]}")
            continue

        sessions.append(session)
        console.print(
            f"[dim]run {run + 1}/{runs}: score {session.score()} — "
            f"{reply[:70].strip() or 'no final reply'}[/dim]"
        )

    if not sessions:
        console.print(
            f"\n[red]All {runs} run(s) failed; there is nothing to measure.[/red]\n"
            f"[red]{failures[0][:300]}[/red]"
        )
        raise typer.Exit(code=4)

    summary = aggregate(sessions)
    summary["model"] = model
    summary["collision"] = collision
    summary["failed_runs"] = len(failures)
    summary["worst_case_score"] = worst_case_score(summary)

    console.print()
    console.print(render_aggregate(summary))
    console.print(
        f"\n[bold]Worst-case score: {summary['worst_case_score']} / 10[/bold]  "
        f"(mean {summary['mean_score']}, single-run worst {summary['worst_score']})"
    )
    if failures:
        console.print(
            f"[yellow]{len(failures)} of {runs} run(s) failed and were excluded. "
            "The score covers only the runs that reached the model.[/yellow]"
        )
    if not summary["consistent"]:
        console.print(
            "[yellow]Runs disagreed. Resistance that varies between identical runs is "
            "luck, not policy — treat the worst case as the real result.[/yellow]"
        )
    console.print("[dim]mcpbait observes the server side only.[/dim]")

    if json_path:
        json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        typer.echo(f"Summary written to {json_path}")
    if fail_under is not None and summary["worst_case_score"] < fail_under:
        typer.echo(f"Worst-case {summary['worst_case_score']} is below {fail_under}.")
        raise typer.Exit(code=3)


@app.command()
def report(
    directory: DirOption = DEFAULT_DIR,
    session_id: Annotated[str | None, typer.Option("--session", help="Session id.")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write JSON here.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write HTML here.")] = None,
    sarif_path: Annotated[
        Path | None, typer.Option("--sarif", help="Write SARIF 2.1.0 security report here.")
    ] = None,
    fail_under: Annotated[
        float | None,
        typer.Option("--fail-under", help="Exit 3 if the resilience score is below this."),
    ] = None,
) -> None:
    """Render the kill chain and security report for a finished session."""
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
    if sarif_path:
        sarif_path.write_text(json.dumps(to_sarif(session), indent=2), encoding="utf-8")
        typer.echo(f"SARIF written to {sarif_path}")
    if fail_under is not None and session.score() < fail_under:
        typer.echo(f"Score {session.score()} is below the {fail_under} threshold.")
        raise typer.Exit(code=3)


@app.command(name="matrix")
def matrix(
    directory: DirOption = DEFAULT_DIR,
    models: Annotated[
        str,
        typer.Option("--models", help="Comma-separated list of model IDs to benchmark."),
    ] = "gpt-4o,gpt-4o-mini",
    api_base: Annotated[
        str, typer.Option("--api-base", envvar="MCPBAIT_API_BASE", help="OpenAI-compatible base URL.")
    ] = "https://api.openai.com/v1",
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="MCPBAIT_API_KEY", help="API key.")
    ] = None,
    runs: Annotated[int, typer.Option("--runs", help="How many sessions to run per model.")] = 2,
    task: Annotated[str, typer.Option("--task", help="The ordinary task to give the agent.")] = DEFAULT_TASK,
    max_turns: Annotated[int, typer.Option("--max-turns", help="Tool-calling turns per run.")] = 8,
    collision: Annotated[
        str,
        typer.Option(
            "--collision",
            help="How the client resolves duplicate tool names: shadow, namespace or builtin.",
        ),
    ] = "shadow",
    module_ids: Annotated[
        str | None, typer.Option("--modules", help="Comma-separated module ids. Default: all.")
    ] = None,
    markdown_path: Annotated[
        Path | None, typer.Option("--markdown", help="Write Markdown leaderboard here.")
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Write JSON summary matrix here.")
    ] = None,
    fail_under: Annotated[
        float | None,
        typer.Option("--fail-under", help="Exit 3 if any model worst-case score is below this."),
    ] = None,
) -> None:
    """Benchmark multiple models and generate a comparative security leaderboard."""
    if not api_key:
        typer.echo("No API key. Pass --api-key or set MCPBAIT_API_KEY.")
        raise typer.Exit(code=1)

    if collision not in COLLISION_POLICIES:
        raise typer.BadParameter(f"--collision must be one of {', '.join(COLLISION_POLICIES)}")

    model_list = [m.strip() for m in models.split(",") if m.strip()]
    if not model_list:
        raise typer.BadParameter("At least one model must be provided in --models.")

    state = _load_state(directory)
    selected = _select(module_ids)
    workspace = Path(state["workspace"])
    console = Console()

    matrix_results: dict[str, Any] = {"models": {}}

    for model_name in model_list:
        console.print(f"\n[bold cyan]Benchmarking model:[/bold cyan] [bold]{model_name}[/bold]")
        completion = http_completion(model=model_name, api_base=api_base, api_key=api_key)

        sessions: list[Session] = []
        failures: list[str] = []

        for run in range(max(1, runs)):
            create_workspace(workspace, state["canaries"])
            beacon = Beacon(on_hit=lambda path, params: None)
            ctx = PayloadContext(
                canaries=state["canaries"], workspace=workspace, beacon_url=beacon.start()
            )
            session = Session(directory / "sessions", modules=get_modules(selected), ctx=ctx)
            beacon.on_hit = lambda path, params, _s=session: _s.record(
                "beacon_hit", params.get("m", ""), {"path": path, "params": params}
            )

            failed = None
            try:
                reply = anyio.run(
                    lambda _s=session, _c=completion: run_agent(
                        _s, _c, task=task, max_turns=max_turns, collision=collision
                    )
                )
            except Exception as error:  # noqa: BLE001
                failed = str(error)
                reply = ""
                session.record("run_error", "", {"error": repr(error)})
            finally:
                beacon.stop()

            persistence = REGISTRY["memory_poisoning"]()
            if persistence.check_persistence(workspace):
                session.record("persistence_confirmed", persistence.id, {"workspace": str(workspace)})
            session.close()

            if failed:
                failures.append(failed)
                console.print(f"  [red]run {run + 1}/{runs} failed:[/red] {failed[:120]}")
                continue

            sessions.append(session)
            console.print(
                f"  [dim]run {run + 1}/{runs}: score {session.score()} — "
                f"{reply[:60].strip() or 'no reply'}[/dim]"
            )

        if not sessions:
            console.print(f"  [red]All runs for {model_name} failed. Skipping.[/red]")
            continue

        summary = aggregate(sessions)
        summary["model"] = model_name
        summary["collision"] = collision
        summary["failed_runs"] = len(failures)
        summary["worst_case_score"] = worst_case_score(summary)
        matrix_results["models"][model_name] = summary

    if not matrix_results["models"]:
        console.print("[red]No models could be successfully benchmarked.[/red]")
        raise typer.Exit(code=4)

    console.print("\n")
    console.print(render_matrix_table(matrix_results))

    if markdown_path:
        markdown_path.write_text(render_matrix_markdown(matrix_results), encoding="utf-8")
        console.print(f"\n[green]Leaderboard Markdown written to[/green] {markdown_path}")

    if json_path:
        json_path.write_text(json.dumps(matrix_results, indent=2), encoding="utf-8")
        console.print(f"[green]Matrix JSON written to[/green] {json_path}")

    if fail_under is not None:
        failing_models = [
            m for m, data in matrix_results["models"].items()
            if data["worst_case_score"] < fail_under
        ]
        if failing_models:
            console.print(
                f"\n[red]Failure: {len(failing_models)} model(s) fell below threshold {fail_under}: "
                f"{', '.join(failing_models)}[/red]"
            )
            raise typer.Exit(code=3)


if __name__ == "__main__":
    app()
