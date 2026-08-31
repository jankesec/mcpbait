# Security policy

## What mcpbait is for

mcpbait tests agents **you own or have written permission to test**. It is built so that
this is the only thing it can do:

- The server only runs if you add it to an agent configuration by hand. There is no
  path by which mcpbait reaches a third party's agent.
- The beacon binds `127.0.0.1` on a kernel-assigned port. Remote callbacks are not
  implemented.
- Every planted credential is synthetic and carries the literal marker `MCPBAIT`.
  mcpbait never reads, scans or transmits your real files.
- Reports redact canary values to a prefix, because reports end up in screenshots.

## What mcpbait will not accept

Contributions in these categories are declined regardless of quality:

- Detection or EDR evasion.
- Anything designed to operate against infrastructure the operator does not control.
- Modules that exfiltrate to a remote endpoint by default.

The project's usefulness depends on it being something a defender can run at work.

## Found a real flaw in a vendor's agent?

mcpbait will happily prove that a shipping product leaks. If that happens:

1. Report it to the vendor first, through their published security contact.
2. Give them reasonable time to fix it before publishing.
3. Share the redacted session JSON rather than raw logs — the raw log contains your
   full canary values and the arguments your agent sent.

## Reporting a vulnerability in mcpbait itself

Open a GitHub security advisory on this repository rather than a public issue.
