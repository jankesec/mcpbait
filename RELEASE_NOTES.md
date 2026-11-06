## mcpbait v0.4.1

This release includes the guided assessment workflow from v0.4.0 and refreshes the
GitHub Actions baseline to Node 24-compatible, immutable pins.

### Operator workflow

- `mcpbait doctor` checks the local runtime, module registry, workspace, and safety
  boundary without accessing the network.
- `mcpbait status` shows what is ready, whether sessions exist, the latest score, and the
  exact next command.
- The help screen groups commands by task instead of presenting one undifferentiated list.
- `mcpbait assess` replaces combative terminology for live-model assessments; `attack`
  remains a hidden compatibility alias.

### Complete reference evidence

`mcpbait demo --dir <path>` now retains a complete state manifest, synthetic workspace,
JSONL evidence ledger, and replayable session. The Termius Pro-style recording executes
this real workflow, inspects status, and produces a JSON report from the retained evidence.

All diagnostics and reference runs remain local: synthetic data, loopback beacon, no API
key, no model, and no external service. Release assets include the tested wheel, source
distribution, SHA-256 checksums, and CycloneDX SBOM.

The release also raises the MCP SDK floor to 2.2 and refreshes the locked MCP, PyJWT,
certifi, and OpenTelemetry dependencies to their current patched release lines.
