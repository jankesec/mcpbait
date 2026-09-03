"""Installing into -- and backing out of -- a real MCP client configuration.

`mcpbait.clients` is the only code in this project that writes outside the decoy
workspace: it edits the live configuration of Claude Desktop, Cursor, Windsurf and
Cline in place. That makes two promises load bearing. The operator must be able to
undo an install exactly, and nothing they did not ask about -- other MCP servers,
unrelated editor settings -- may be disturbed on the way.

Every test redirects the client locations into `tmp_path` before touching anything,
so the suite exercises the real path resolution without the developer's own config
ever being a candidate.
"""

import json
from pathlib import Path

import pytest

from mcpbait import clients
from mcpbait.clients import (
    SUPPORTED_CLIENTS,
    install_into_client,
    resolve_config_path,
    uninstall_from_client,
)

ALIAS = "system-indexer"


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Point every location `resolve_config_path` can return at a throwaway home.

    This is the safety net rather than a convenience. `install_into_client` writes to
    `resolve_config_path(client)` whenever no explicit path is given, so a test that
    forgets to pass one would otherwise edit the machine's real Claude Desktop config.
    Home, %APPDATA% and the working directory are all moved, because the module reads
    all three.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    # Cursor prefers a workspace-local .cursor/mcp.json, resolved against the cwd.
    monkeypatch.chdir(tmp_path)
    return home


@pytest.fixture
def state_dir(tmp_path):
    """The `--dir` a real install would point the server at."""
    directory = tmp_path / "state"
    (directory / "sessions").mkdir(parents=True)
    return directory


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _servers(path):
    return _read(path)["mcpServers"]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_no_client_resolves_outside_the_patched_home(client, fake_home):
    """The containment the rest of this file depends on, asserted rather than assumed.

    If this fails, every other test here is quietly writing to the real user config.
    """
    path = resolve_config_path(client)
    assert path.name.endswith(".json")
    assert fake_home in path.parents, f"{client} escaped the patched home: {path}"


@pytest.mark.parametrize("system", ["Darwin", "Windows", "Linux"])
@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_every_platform_branch_stays_inside_the_patched_home(
    client, system, fake_home, monkeypatch
):
    """The per-OS branches decide which real file gets rewritten, so all three run.

    A wrong path here is not a cosmetic bug: it is mcpbait writing an agent config
    somewhere the operator does not know to look, and cannot uninstall from.
    """
    monkeypatch.setattr(clients.platform, "system", lambda: system)
    path = resolve_config_path(client)
    assert path.name.endswith(".json")
    assert fake_home in path.parents, f"{client} on {system} escaped: {path}"


@pytest.mark.parametrize("client", ["claude-desktop", "cline"])
def test_windows_without_appdata_falls_back_under_home(client, fake_home, monkeypatch):
    """%APPDATA% is not guaranteed to be set; the fallback must still be the user's own."""
    monkeypatch.setattr(clients.platform, "system", lambda: "Windows")
    monkeypatch.delenv("APPDATA", raising=False)
    path = resolve_config_path(client)
    assert fake_home / "AppData" / "Roaming" in path.parents


def test_cursor_prefers_a_workspace_config_over_the_global_one(fake_home, tmp_path):
    """A project-local .cursor wins, which is where a scoped red team run belongs."""
    (tmp_path / ".cursor").mkdir()
    assert resolve_config_path("cursor") == Path(".cursor") / "mcp.json"


def test_an_unknown_client_is_refused_by_name(fake_home):
    """The CLI turns this into exit code 1; a silent default would write somewhere random."""
    with pytest.raises(ValueError, match="Unsupported client"):
        resolve_config_path("emacs")


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_then_uninstall_restores_the_config(client, fake_home, state_dir):
    """Uninstall has to be a real undo, so the comparison is on bytes, not parsed JSON.

    The file is seeded in the canonical form `install_into_client` itself emits --
    the module reformats whatever it rewrites, and comparing against a hand-formatted
    original would measure indentation instead of the undo.
    """
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    original = json.dumps(
        {"mcpServers": {"notion": {"command": "npx", "args": ["-y", "notion-mcp"]}}}, indent=2
    )
    config.write_text(original, encoding="utf-8")

    install_into_client(client, ALIAS, state_dir)
    assert config.read_text(encoding="utf-8") != original, "install wrote nothing"

    uninstall_from_client(client, ALIAS)
    assert config.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_installing_twice_is_idempotent(client, fake_home, state_dir):
    """Re-running install after editing the decoy must not leave two servers behind.

    A duplicate entry would double the poisoned tool list the agent sees and quietly
    invalidate the run it is meant to measure.
    """
    config = install_into_client(client, ALIAS, state_dir)
    after_first = config.read_text(encoding="utf-8")

    install_into_client(client, ALIAS, state_dir)
    assert config.read_text(encoding="utf-8") == after_first
    assert list(_servers(config)) == [ALIAS]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_uninstall_leaves_unrelated_servers_alone(client, fake_home, state_dir):
    """The operator's other MCP servers are not ours to remove."""
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        json.dumps({"mcpServers": {"github": {"command": "npx"}, "notion": {"command": "uvx"}}}),
        encoding="utf-8",
    )

    install_into_client(client, ALIAS, state_dir)
    uninstall_from_client(client, ALIAS)

    servers = _servers(config)
    assert set(servers) == {"github", "notion"}
    assert servers["github"] == {"command": "npx"}


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_preserves_unrelated_top_level_keys(client, fake_home, state_dir):
    """Editor configs hold far more than mcpServers, and all of it must survive.

    These files carry themes, keybindings and account settings. Losing them to a
    security test would do more damage than the attack the test is measuring.
    """
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        json.dumps(
            {
                "theme": "dark",
                "telemetry": {"enabled": False},
                "globalShortcut": "Cmd+Shift+Space",
                "mcpServers": {"github": {"command": "npx"}},
            }
        ),
        encoding="utf-8",
    )

    install_into_client(client, ALIAS, state_dir)

    data = _read(config)
    assert data["theme"] == "dark"
    assert data["telemetry"] == {"enabled": False}
    assert data["globalShortcut"] == "Cmd+Shift+Space"
    assert ALIAS in data["mcpServers"]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_creates_a_missing_config_file(client, fake_home, state_dir):
    """A client that has never been configured has no file, and no parent directory."""
    config = resolve_config_path(client)
    assert not config.exists()

    returned = install_into_client(client, ALIAS, state_dir)

    assert returned == config
    assert config.is_file()
    assert list(_servers(config)) == [ALIAS]
    assert not config.with_suffix(".json.bak").exists(), "nothing existed to back up"


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_points_the_client_at_the_state_directory(client, fake_home, state_dir):
    """The written command is what the client will actually spawn."""
    config = install_into_client(client, ALIAS, state_dir)
    entry = _servers(config)[ALIAS]
    assert entry["command"] == "uvx"
    assert entry["args"] == ["mcpbait", "serve", "--dir", str(state_dir.resolve())]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_a_malformed_mcpservers_value_is_replaced_rather_than_indexed(client, fake_home, state_dir):
    """A non-object mcpServers is unusable to the client anyway, so repairing it is safe."""
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"theme": "dark", "mcpServers": "broken"}), encoding="utf-8")

    install_into_client(client, ALIAS, state_dir)

    data = _read(config)
    assert data["theme"] == "dark"
    assert list(data["mcpServers"]) == [ALIAS]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_refuses_to_clobber_unparseable_json(client, fake_home, state_dir):
    """Failing to parse a config is exactly when overwriting it is least acceptable.

    Unparseable does not mean worthless: a trailing comma or a half-finished edit
    still holds everything the operator configured. The only safe move is to report
    it and leave the bytes alone.
    """
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    broken = '{"mcpServers": {"github": {"command": "npx"},}}'  # trailing comma
    config.write_text(broken, encoding="utf-8")

    with pytest.raises(ValueError):
        install_into_client(client, ALIAS, state_dir)

    assert config.read_text(encoding="utf-8") == broken


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_uninstall_leaves_unparseable_json_untouched(client, fake_home):
    """Uninstall already gets this right, and is the reason the install bug stands out."""
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    broken = "{not json at all"
    config.write_text(broken, encoding="utf-8")

    uninstall_from_client(client, ALIAS)

    assert config.read_text(encoding="utf-8") == broken


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_uninstall_is_a_no_op_when_nothing_was_installed(client, fake_home):
    """Uninstalling from a client that was never configured must not create a file."""
    config = resolve_config_path(client)

    returned = uninstall_from_client(client, ALIAS)

    assert returned == config
    assert not config.exists()


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_the_disguise_alias_round_trips(client, fake_home, state_dir):
    """`--as` exists so the agent is not tipped off by reading 'mcpbait' in its config.

    A disguise that install honours but uninstall does not would leave an innocuous
    looking adversarial server installed permanently, which is the worst outcome the
    module can produce.
    """
    disguise = "workspace-search"
    config = install_into_client(client, disguise, state_dir)
    assert list(_servers(config)) == [disguise]

    uninstall_from_client(client, disguise)
    assert _servers(config) == {}


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_uninstall_under_the_wrong_alias_removes_nothing(client, fake_home, state_dir):
    """Guessing the alias must not be treated as close enough to delete something."""
    config = install_into_client(client, "workspace-search", state_dir)

    uninstall_from_client(client, ALIAS)

    assert list(_servers(config)) == ["workspace-search"]


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_install_backs_up_the_file_it_is_about_to_rewrite(client, fake_home, state_dir):
    """The CLI promises this backup by path, so the promise is tested by path."""
    config = resolve_config_path(client)
    config.parent.mkdir(parents=True, exist_ok=True)
    original = json.dumps({"mcpServers": {"github": {"command": "npx"}}})
    config.write_text(original, encoding="utf-8")

    install_into_client(client, ALIAS, state_dir)

    backup = config.with_suffix(".json.bak")
    assert backup.is_file()
    assert backup.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_an_explicit_config_path_overrides_the_resolved_one(client, fake_home, tmp_path, state_dir):
    """--config-path is how an operator tests a client mcpbait does not know about."""
    explicit = tmp_path / "elsewhere" / "mcp.json"

    returned = install_into_client(client, ALIAS, state_dir, custom_path=explicit)

    assert returned == explicit
    assert list(_servers(explicit)) == [ALIAS]
    assert not resolve_config_path(client).exists(), "the resolved path was written anyway"

    uninstall_from_client(client, ALIAS, custom_path=explicit)
    assert _servers(explicit) == {}
