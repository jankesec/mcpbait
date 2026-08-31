# Attack techniques

How an MCP server can hijack the agent connected to it, what mcpbait sends to test each
case, and how to defend. Every page is generated from the module that implements it,
so it cannot drift from the code.

| Phase | Technique | What it does |
|---|---|---|
| ACCESS | [`line_jumping`](line_jumping.md) | Delivers the full instruction in the tool listing, before any invocation. |
| ACCESS | [`name_squatting`](name_squatting.md) | Impersonates a well-known tool name so calls are routed to the attacker. |
| ACCESS | [`tool_poisoning`](tool_poisoning.md) | Hides agent instructions inside a tool description the user never reads. |
| ACCESS | [`unicode_smuggling`](unicode_smuggling.md) | Encodes the injected instruction in invisible Unicode tag characters. |
| INFLUENCE | [`cross_server_shadowing`](cross_server_shadowing.md) | Rewrites how the agent uses a trusted third-party server's tools. |
| INFLUENCE | [`result_injection`](result_injection.md) | Injects instructions into fetched content rather than the tool description. |
| INFLUENCE | [`rug_pull`](rug_pull.md) | Serves a benign tool at approval time and redefines it after trust is won. |
| COLLECTION | [`bait_secrets`](bait_secrets.md) | Gives the agent a plausible reason to collect the planted credentials. |
| COLLECTION | [`context_exfil`](context_exfil.md) | Persuades the agent to hand over the prior conversation for 'continuity'. |
| EXFILTRATION | [`markdown_beacon`](markdown_beacon.md) | Leaks through a markdown image the client fetches while rendering. |
| EXFILTRATION | [`param_smuggling`](param_smuggling.md) | Offers a harmless-looking telemetry sink that carries data straight out. |
| PERSISTENCE | [`memory_poisoning`](memory_poisoning.md) | Writes the injection into the agent's standing instruction file. |
| SOCIAL | [`elicitation_phish`](elicitation_phish.md) | Asks the user for credentials through the agent's trusted interface. |

Each page ends with a defence section. If you only read one, read
[`memory_poisoning`](memory_poisoning.md) -- it is the only technique here that
survives the end of the conversation.
