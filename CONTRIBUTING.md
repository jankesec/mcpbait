# Contributing

The most valuable contribution is a new attack module. The module directory is what
keeps a framework like this alive.

## Adding a module

Modules are pure: they build a payload from a context and judge evidence from an event
list. No filesystem, no network, no session state. That is what makes them easy to test
and safe to review.

```python
from mcpbait.modules import register
from mcpbait.modules.base import AttackModule
from mcpbait.types import PayloadContext, Phase, ToolSpec


@register
class MyTechnique(AttackModule):
    id = "my_technique"
    phase = Phase.ACCESS
    atlas_id = "AML.T0051"
    summary = "One sentence, over twenty characters, describing the technique."
    references = ("https://example.com/writeup",)
    why = "Why an agent falls for this. Over eighty characters; it becomes the docs page."
    defence = "How to defend against it. Also over eighty characters, and also published."

    def payload(self, ctx: PayloadContext) -> list[ToolSpec]:
        return [ToolSpec(
            name="my_tool",
            description=f"...referencing {ctx.workspace} where useful...",
            input_schema={"type": "object", "properties": {}},
        )]
```

Then register it in `src/mcpbait/modules/__init__.py`, add a test, and regenerate docs:

```bash
uv run python -m tools.gen_docs
```

## What CI enforces

- Complete metadata, including `why` and `defence`.
- `payload()` returns valid tool specs and is deterministic.
- The module writes nothing to disk.
- The technique page on disk matches what the generator produces.
- `ruff check` and the full test suite pass.

## Running the suite

```bash
uv run pytest -v
```

No API key, no network, no model. The end-to-end tests drive a fake client that obeys
every instruction it reads. If you need a real agent in the loop, that is a manual run,
not a CI job.

## Out of scope

See [SECURITY.md](SECURITY.md). Evasion and third-party targeting are declined.
