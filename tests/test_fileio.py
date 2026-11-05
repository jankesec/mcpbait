from mcpbait.fileio import atomic_write_text, open_private_append


def test_atomic_write_replaces_content_with_private_permissions(tmp_path):
    target = tmp_path / "evidence.json"
    target.write_text("stale", encoding="utf-8")

    atomic_write_text(target, '{"status":"complete"}')

    assert target.read_text(encoding="utf-8") == '{"status":"complete"}'
    assert target.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".evidence.json.*"))


def test_private_append_creates_owner_only_log(tmp_path):
    target = tmp_path / "session.jsonl"
    with open_private_append(target) as handle:
        handle.write("one\n")
    with open_private_append(target) as handle:
        handle.write("two\n")

    assert target.read_text(encoding="utf-8") == "one\ntwo\n"
    assert target.stat().st_mode & 0o777 == 0o600


def test_atomic_write_honours_requested_mode(tmp_path):
    target = tmp_path / "client.json"
    atomic_write_text(target, "{}", mode=0o640)
    assert target.stat().st_mode & 0o777 == 0o640
    assert target.is_file()
