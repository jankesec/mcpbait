"""One-click configuration and integration with popular MCP-speaking clients.

Enables safe automated installation and uninstallation of disguised mcpbait servers
in Claude Desktop, Cursor, Windsurf, and Cline.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
from pathlib import Path
from typing import Any

SUPPORTED_CLIENTS = ("claude-desktop", "cursor", "windsurf", "cline")


def resolve_config_path(client: str) -> Path:
    """Resolve standard configuration file location for the given client."""
    client_key = client.lower().replace("_", "-")
    system = platform.system()
    home = Path.home()

    if client_key == "claude-desktop":
        if system == "Darwin":
            return (
                home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            )
        if system == "Windows":
            appdata = os.environ.get("APPDATA")
            return (
                (Path(appdata) if appdata else home / "AppData" / "Roaming")
                / "Claude"
                / "claude_desktop_config.json"
            )
        return home / ".config" / "Claude" / "claude_desktop_config.json"

    if client_key == "cursor":
        # Local workspace takes priority if present, otherwise global
        workspace_mcp = Path(".cursor") / "mcp.json"
        if workspace_mcp.parent.is_dir():
            return workspace_mcp
        return home / ".cursor" / "mcp.json"

    if client_key == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json"

    if client_key == "cline":
        if system == "Darwin":
            return (
                home
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
            )
        if system == "Windows":
            appdata = os.environ.get("APPDATA")
            base = Path(appdata) if appdata else home / "AppData" / "Roaming"
            return (
                base
                / "Code"
                / "User"
                / "globalStorage"
                / "saoudrizwan.claude-dev"
                / "settings"
                / "cline_mcp_settings.json"
            )
        return (
            home
            / ".config"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json"
        )

    raise ValueError(
        f"Unsupported client '{client}'. Supported clients: {', '.join(SUPPORTED_CLIENTS)}"
    )


def install_into_client(
    client: str,
    server_name: str,
    state_dir: Path,
    custom_path: Path | None = None,
) -> Path:
    """Inject mcpbait server configuration into the target client configuration file."""
    config_path = custom_path or resolve_config_path(client)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    data: dict[str, Any] = {}
    if config_path.is_file():
        # Parse before backing up. A config we cannot read is a config we must not
        # rewrite: falling back to an empty dict here would replace the user's editor
        # configuration with nothing but our own entry, and the backup written a moment
        # earlier would be overwritten by the next install. cli.py turns ValueError
        # into a clean exit rather than a traceback.
        raw = config_path.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"{config_path} is not valid JSON ({error}). Refusing to overwrite it -- "
                "fix or move the file, then run install again."
            ) from error
        if not isinstance(parsed, dict):
            raise ValueError(
                f"{config_path} holds {type(parsed).__name__}, not a JSON object. "
                "Refusing to overwrite it."
            )
        data = parsed

        # Back up the state before mcpbait touched it. Once our entry is present the
        # file is no longer that state, so copying again would bury the real original.
        existing = data.get("mcpServers")
        if not (isinstance(existing, dict) and server_name in existing):
            shutil.copy2(config_path, config_path.with_suffix(".json.bak"))

    if "mcpServers" not in data or not isinstance(data["mcpServers"], dict):
        data["mcpServers"] = {}

    data["mcpServers"][server_name] = {
        "command": "uvx",
        "args": ["mcpbait", "serve", "--dir", str(state_dir.resolve())],
    }

    config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return config_path


def uninstall_from_client(
    client: str,
    server_name: str,
    custom_path: Path | None = None,
) -> Path:
    """Remove mcpbait server configuration from the target client configuration file."""
    config_path = custom_path or resolve_config_path(client)
    if not config_path.is_file():
        return config_path

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return config_path

    if (
        "mcpServers" in data
        and isinstance(data["mcpServers"], dict)
        and server_name in data["mcpServers"]
    ):
        del data["mcpServers"][server_name]
        config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return config_path
