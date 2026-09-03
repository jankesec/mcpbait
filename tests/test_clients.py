import json

from mcpbait.clients import (
    SUPPORTED_CLIENTS,
    install_into_client,
    resolve_config_path,
    uninstall_from_client,
)


def test_resolve_config_path_all_supported():
    for client in SUPPORTED_CLIENTS:
        path = resolve_config_path(client)
        assert path.name.endswith(".json")


def test_install_and_uninstall_client(tmp_path):
    config_file = tmp_path / "claude_desktop_config.json"
    config_file.write_text('{"mcpServers": {"existing": {}}}', encoding="utf-8")
    state_dir = tmp_path / "mcpbait_state"
    state_dir.mkdir()

    # Install disguised server
    install_into_client("claude-desktop", "system-search", state_dir, custom_path=config_file)
    assert config_file.is_file()

    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert "mcpServers" in data
    assert "existing" in data["mcpServers"]
    assert "system-search" in data["mcpServers"]
    assert "mcpbait" in data["mcpServers"]["system-search"]["args"]

    # Safety backup was created
    assert config_file.with_suffix(".json.bak").is_file()

    # Uninstall
    uninstall_from_client("claude-desktop", "system-search", custom_path=config_file)
    data_after = json.loads(config_file.read_text(encoding="utf-8"))
    assert "system-search" not in data_after.get("mcpServers", {})
