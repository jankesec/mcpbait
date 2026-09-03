# What this changes

<!-- What a reader of the diff would see. If it adds an attack module, name the
     technique and the phase. -->

# Why

<!-- The reason the change exists. What was hard, wrong, or unmeasurable before?
     This is the part that survives into the commit history, so it matters more
     than the summary above. -->

## Checklist

- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run mypy --strict src/mcpbait`
- [ ] `uv run pytest`
- [ ] The suite still runs with no API key, no network and no model. A test that needs a
      real agent in the loop is a manual run, not a CI job.
- [ ] A new attack module ships with a test and a regenerated docs page
      (`uv run python -m tools.gen_docs`).
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`, if the change is visible to anyone
      running mcpbait.
