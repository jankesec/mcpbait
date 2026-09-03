# 🚀 mcpbait Launch & Distribution Kit

This kit contains ready-to-publish posts, community write-ups, and pull request templates for launching `mcpbait` to the global cybersecurity and AI engineering communities.

---

## 1. Hacker News — Show HN Post

**Target URL:** `https://news.ycombinator.com/submit`  
**Title:** `Show HN: mcpbait – Red teaming framework that proves whether an MCP agent can be hijacked`  
**URL:** `https://github.com/jankesec/mcpbait` (or leave URL blank and post as text with repo link)

### Text:
```markdown
Hey HN,

Over the past months, everyone has been rushing to connect LLM agents to tools using Anthropic's Model Context Protocol (MCP). While the protocol solves interoperability, it creates a massive new attack surface: **rogue or compromised MCP servers**.

Most existing AI security scanners prompt a model and ask "did it jailbreak?", or run static AST scans on Python/TS servers. 

We built **mcpbait** (https://github.com/jankesec/mcpbait) with a different premise: **the adversary and the verifier are the same process**. 

Instead of attacking the model from the front, `mcpbait` becomes the malicious MCP server itself. It lets your agent (Claude Desktop, Cursor, Windsurf, custom agents) do ordinary work, but serves adversarial tool definitions and results across 13 distinct kill-chain techniques:

1. **Tool Schema Poisoning & Rug Pulls:** Dynamically altering input schemas after initial discovery.
2. **Memory & Persistence Poisoning:** Injecting persistent instructions into standing workspace rulefiles (`.cursorrules`, `CLAUDE.md`, `AGENTS.md`).
3. **Markdown Beacons:** Bypassing model refusals by exploiting client UI markdown image rendering to exfiltrate secrets without model compliance.
4. **Zero-Width / Unicode Smuggling:** Hiding injection vectors inside invisible tokens.
5. **In-Process Canary Exfiltration:** Planting synthetic credentials in decoy workspaces and detecting leaks when the agent hands them back as tool arguments — zero external C2, zero DNS canaries, fully offline.

### Quick Demo (No setup needed)
```bash
uvx mcpbait demo
```

It outputs a structured timeline table and an automated **Resilience Score (0 to 10)**. We also added SARIF 2.1.0 exports and an automated multi-model benchmark matrix (`mcpbait matrix`).

Would love feedback from anyone building MCP clients, servers, or agent orchestration layers!
```

---

## 2. Reddit — /r/netsec Post

**Target Subreddit:** `r/netsec`  
**Title:** `mcpbait: In-process Red Teaming and Resilience Auditing Framework for Model Context Protocol (MCP) Agents`

### Body:
```markdown
**GitHub Repository:** https://github.com/jankesec/mcpbait  
**PyPI:** `pip install mcpbait` / `uvx mcpbait`  
**License:** Apache 2.0

### Summary
As Model Context Protocol (MCP) adoption grows across developer tools and enterprise workflows, agent compromise via untrusted MCP servers has become a critical threat vector. 

`mcpbait` is an open-source offensive security tool designed to simulate malicious MCP servers and measure how agents respond under 13 offensive techniques mapped to MITRE ATLAS.

### Key Capabilities
- **Local / Air-gapped Verification:** The test runner mints synthetic canaries in an isolated decoy workspace. When the agent leaks a secret into an adversarial tool argument, the verifier intercepts it directly. No external DNS/HTTP infrastructure required.
- **Protocol-Level Attacks:**
  - *Rug Pulls:* Server modifies tool descriptions/schemas mid-session.
  - *Markdown Image Beacons:* Triggers UI-level data exfiltration on the client renderer.
  - *Standing Rule Persistence:* Verifies if the agent can be tricked into modifying `.cursorrules`, `AGENTS.md`, or system memory files.
- **Reporting & CI/CD Integration:**
  - Standardized Resilience Score (0.0 – 10.0)
  - SARIF 2.1.0 output for GitHub Advanced Security / CodeQL tabs
  - Standalone dark-mode HTML executive reports
  - Multi-model comparative leaderboard generator (`mcpbait matrix`)

Feedback, issues, and new technique contributions are very welcome!
```

---

## 3. Reddit — /r/LocalLLaMA Post

**Target Subreddit:** `r/LocalLLaMA`  
**Title:** `We built an open-source framework (mcpbait) to test how easily local and cloud agents get hijacked by malicious MCP servers`

### Body:
```markdown
Hey everyone!

With local agent tooling exploding (Ollama + Open-WebUI, Cursor, Continue, Cline), many users are connecting community-created MCP servers without sandboxing.

We released **mcpbait** (https://github.com/jankesec/mcpbait) to measure how resistant different open-weights (Llama 3.3, DeepSeek, Qwen 2.5) and closed models are when a rogue MCP server tries to:
1. Steal synthetic environment variables via hidden canary tracking
2. Inject persistent backdoors into `.cursorrules` / local config
3. Exploit markdown renderers to ping back telemetry

You can run the entire 13-module test offline in 10 seconds:
```bash
uvx mcpbait demo
```

Or test local models over an OpenAI-compatible endpoint:
```bash
mcpbait attack --api-base http://localhost:11434/v1 --model llama3.3:70b
```

Check out the repo and let us know what models you'd like to see benchmarked in the leaderboard!
```

---

## 4. X (Twitter) Launch Thread

**Post 1 (Hook):**
> 🚨 What happens when your AI agent connects to a rogue MCP server?
>
> Most tools only test prompt injection from the user. But in the agent era, the SERVER can be the attacker.
>
> Introducing **mcpbait** — an open-source Red Teaming framework for Model Context Protocol agents:
> 🔗 https://github.com/jankesec/mcpbait
> 🧵👇 (1/5)

**Post 2 (How it works):**
> Instead of scanning static ASTs, mcpbait BECOMES the malicious MCP server.
>
> It plants synthetic canaries in a decoy workspace and serves 13 attack modules (rug pulls, memory poisoning, markdown beacons, unicode smuggling).
>
> If the agent leaks a secret, it catches it in-process. Zero external C2 needed. (2/5)

**Post 3 (Kill chain & Features):**
> 📊 What you get:
> - Automated Resilience Score (0 to 10)
> - Multi-Model Security Leaderboard (`mcpbait matrix`)
> - SARIF 2.1.0 export for CI/CD
> - Standalone Executive Dark-Mode HTML report (3/5)

**Post 4 (Try it):**
> Test your agent in 10 seconds:
> ```bash
> uvx mcpbait demo
> ```
> GitHub: https://github.com/jankesec/mcpbait
> Star ⭐️, fork, and test your agents! (4/5)

---

## 5. Pull Request Templates for Awesome Lists

### A. For `punkpeye/awesome-mcp-servers` or `wong2/awesome-mcp-servers`
- **Section:** `Security & Testing` or `Developer Tools`
- **Entry:**
  ```markdown
  - [mcpbait](https://github.com/jankesec/mcpbait) - Automated red teaming and resilience auditing framework that tests whether AI agents can be hijacked by rogue MCP servers.
  ```

### B. For `corca-ai/awesome-ai-security` & `jasonwei20/awesome-llm-security`
- **Section:** `Red Teaming & Evaluation Tools`
- **Entry:**
  ```markdown
  - [mcpbait](https://github.com/jankesec/mcpbait) - In-process red teaming framework for Model Context Protocol (MCP) agents with MITRE ATLAS mapping, canary exfiltration, and SARIF exports.
  ```
