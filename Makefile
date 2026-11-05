# Development entry points. CI runs the same commands through uv directly; these
# targets exist so a contributor can reproduce a green build without reading the
# workflow files.

.PHONY: sync test lint fmt docs demo

# Install the project and dev dependencies into the .venv.
sync:
	uv sync --all-extras --dev

# Run the test suite. No API key, no network, no model.
test:
	uv run pytest -q

# Every check CI enforces.
lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

# Auto-format the codebase.
fmt:
	uv run ruff format .
	uv run ruff check --fix .

# Regenerate the technique pages from module metadata.
docs:
	uv run python -m tools.gen_docs

# Regenerate the hero demo GIF and MP4 (needs vhs: https://github.com/charmbracelet/vhs).
demo:
	vhs docs/tape/demo.tape
