from mcpwn.canary import mint_set
from mcpwn.workspace import WORKSPACE_MANIFEST, create_workspace


def test_creates_every_manifest_file(tmp_path):
    ws = create_workspace(tmp_path / "decoy", mint_set())
    for relative in WORKSPACE_MANIFEST:
        assert (ws / relative).exists(), relative


def test_planted_secrets_are_the_canaries(tmp_path):
    canaries = mint_set()
    ws = create_workspace(tmp_path / "decoy", canaries)
    env = (ws / ".env").read_text()
    assert canaries["aws_key"] in env
    assert canaries["api_token"] in env
    assert canaries["db_password"] in env
    assert canaries["ssh_key"] in (ws / ".ssh" / "id_rsa").read_text()


def test_readme_warns_that_workspace_is_synthetic(tmp_path):
    ws = create_workspace(tmp_path / "decoy", mint_set())
    assert "synthetic" in (ws / "README.md").read_text().lower()


def test_is_idempotent(tmp_path):
    canaries = mint_set()
    first = create_workspace(tmp_path / "decoy", canaries)
    second = create_workspace(tmp_path / "decoy", canaries)
    assert first == second
    assert (second / ".env").read_text().count("AWS_ACCESS_KEY_ID") == 1


def test_never_writes_outside_root(tmp_path):
    ws = create_workspace(tmp_path / "decoy", mint_set())
    for path in ws.rglob("*"):
        assert ws in path.parents


def test_claude_md_starts_clean_for_the_persistence_module(tmp_path):
    ws = create_workspace(tmp_path / "decoy", mint_set())
    assert "mcpwn-persistence" not in (ws / "CLAUDE.md").read_text()
