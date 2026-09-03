# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-03

### Fixed

- `install` no longer destroys a client configuration it cannot parse. It caught the
  JSON error, carried on from an empty dict, and rewrote the file as nothing but its own
  entry; the `.bak` copy was rewritten on every run, so a second install buried the real
  original. It now refuses, names the file, and exits cleanly. `uninstall` was already
  correct.
- `check_persistence` is part of the `AttackModule` contract instead of living on
  `memory_poisoning` and being reached by name through the registry in four duplicated
  blocks. A third-party persistence module can now take part in the kill chain.
- `Session.ctx` is no longer optional. Three call sites dereferenced it without a check,
  one of them passing the possible `None` to a signature that does not accept one.

### Added

- `mcpbait --version`.
- Inline types are shipped to consumers (PEP 561 `py.typed`).
- Changelog, code of conduct, issue and pull request templates, and pre-commit hooks.
- Dependabot, CodeQL, OpenSSF Scorecard, a CycloneDX SBOM on each release, and explicit
  PyPI attestations. Every workflow action reference is pinned to a commit SHA, and every
  workflow and job declares least-privilege permissions.
- The demo recording is generated from `docs/tape/demo.tape` rather than captured by hand.

### Changed

- `mypy --strict`, `ruff format` and a 92% coverage floor are blocking CI gates, across
  Python 3.11, 3.12 and 3.13. Coverage went from 87% to 93%, and `clients.py` -- the only
  code here that writes outside the decoy workspace -- from 67% to 100%.
- Adopted a curated ruff ruleset in place of the line-length-only configuration.

## [0.2.0] - 2026-09-03

### Added

- `mcpbait matrix` benchmarks several models in one command and renders a comparative
  leaderboard, so a resilience score can be read as a ranking rather than a lone number.
  Writes Markdown with `--markdown` and JSON with `--json`, and gates CI with
  `--fail-under`.
- SARIF 2.1.0 export via `mcpbait report --sarif`. Findings land in GitHub code scanning
  and any other SARIF consumer, which puts agent hijacking in the same queue as the rest
  of a team's security backlog.
- `mcpbait install` and `mcpbait uninstall` write the server into Claude Desktop, Cursor,
  Windsurf and Cline configurations directly. Manual JSON editing was the step most likely
  to be got wrong, and a misconfigured server looks exactly like a resilient agent.
  `--as` disguises the server name so the test stays fair, `--config-path` overrides the
  discovered location, and the original file is kept alongside as `.bak`.
- An executive HTML report via `mcpbait report --html`, for the readers who decide whether
  the finding gets fixed but will not read a terminal transcript.
- `mcpbait badge` renders an offline SVG resilience badge from a session or an explicit
  `--score`. No shields.io round trip, so it works on an air-gapped runner.
- A GitHub Action (`action.yml`) that runs the kill chain in a workflow and fails the build
  below a score threshold.
- Publishing to PyPI from a tag through Trusted Publishing, so releases carry no long-lived
  token.

## [0.1.0] - 2026-09-01

### Added

- The session engine: it mints canaries, plants them in an isolated decoy workspace, drives
  the modules through the kill chain, and records every observation to an append-only
  session log.
- Canary minting and encoding-tolerant detection. Agents smuggle values in nested objects,
  in keys rather than values, and through common encodings, so tool arguments are flattened
  and normalised before they are scanned.
- Thirteen attack modules across six kill chain phases: ACCESS (`line_jumping`,
  `name_squatting`, `tool_poisoning`, `unicode_smuggling`), INFLUENCE
  (`cross_server_shadowing`, `result_injection`, `rug_pull`), COLLECTION (`bait_secrets`,
  `context_exfil`), EXFILTRATION (`markdown_beacon`, `param_smuggling`), PERSISTENCE
  (`memory_poisoning`) and SOCIAL (`elicitation_phish`). Each is mapped to MITRE ATLAS and
  generates its own technique page.
- A stdio MCP server that advertises the poisoned tool list to any MCP-speaking client, plus
  `mcpbait init` and `mcpbait config` to set a run up.
- A beacon listener bound to `127.0.0.1` on a kernel-assigned port. Out-of-band fetches are
  proved locally, so no external C2 or DNS canary is ever needed and the whole tool runs
  air-gapped.
- `mcpbait demo` runs the full chain against a built-in defenceless reference agent that
  obeys every instruction it reads. It needs no API key, no network and no model, which
  makes the README output reproducible in one command and gives the test suite a
  deterministic worst case to assert against.
- A live agent driver for any OpenAI-compatible endpoint via `mcpbait attack`. One run
  against a non-deterministic model is an anecdote, so `--runs` repeats the session and the
  report leads with the worst outcome seen. `--collision` switches how the client is assumed
  to resolve a duplicate tool name (`shadow`, `namespace` or `builtin`), because that host
  decision alone determines whether `name_squatting` lands.
- The kill chain reporter and its verdict ladder — BLOCKED, IGNORED, BAITED, COMPROMISED —
  scored to a 0.0-10.0 resilience score. The ladder only reports what is observable from the
  server side: a model that silently declined is indistinguishable from one that never saw
  the payload, so the vocabulary stops at IGNORED rather than claiming a refusal.

[Unreleased]: https://github.com/jankesec/mcpbait/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jankesec/mcpbait/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jankesec/mcpbait/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jankesec/mcpbait/releases/tag/v0.1.0
