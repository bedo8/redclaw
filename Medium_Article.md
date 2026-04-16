# AATCK: A MITRE ATT&CK-Style Framework for AI Agent Security

*By Bedo*

---

## The Missing Framework

Enterprises are deploying AI agents in production. SOC agents investigate breaches. Customer agents handle account data. Code agents access private repos. Governance agents make approval decisions.

None of them have been formally security tested — because no framework exists for it.

MITRE ATT&CK covers networks and endpoints. MITRE ATLAS covers adversarial ML. The OWASP Top 10 for LLM Applications covers prompt injection and output handling for language models in isolation. But agents aren't isolated models. They're models with tools, memory, MCP connections, and autonomy. That's a different attack surface, and it needs its own taxonomy.

AATCK — Adversarial AI Tactics, Techniques & Kill Chain — is that taxonomy. 8 attack classes, 47 techniques, and a kill chain specific to autonomous AI systems. I also built a tool called RedClaw that automates these attacks against any agent to validate the framework in practice. This article walks through both.

### Where This Sits Next to Glasswing

This week Anthropic announced Project Glasswing — a $100M initiative to use frontier AI to find vulnerabilities in software infrastructure. It's a significant step. But Glasswing targets code vulnerabilities in systems. AATCK targets behavioral vulnerabilities in agents. Different attack surface. Different framework needed.

---

## Why Agents Are a Different Problem Than LLMs

A language model takes text in and produces text out. The risks are well-understood: prompt injection, hallucination, memorization, harmful outputs. Existing frameworks cover these.

An AI agent is a model with capabilities layered on top: tools it can invoke (file I/O, HTTP requests, shell commands, database queries), persistent memory across turns, MCP server connections exposing third-party tools and data, orchestration logic that delegates to sub-agents, and the autonomy to decide which tools to call and when.

An attacker doesn't need to make the model "say something bad." They need to make the agent *do something bad* — with its own tools, through its own data pipeline, in its actual environment.

That's a different threat model.

---

## The AATCK Framework

AATCK defines eight attack classes. Each targets a specific layer of the agent architecture.

| ID | Tactic | Target Layer | Techniques |
|----|--------|-------------|-----------|
| AATCK-001 | Prompt Injection | Input processing | 8 |
| AATCK-002 | Tool Abuse | Tool invocation | 6 |
| AATCK-003 | Context Poisoning | Memory / context | 7 |
| AATCK-004 | Goal Hijacking | Decision-making | 4 |
| AATCK-005 | MCP Exploitation | External integrations | 5 |
| AATCK-006 | Data Exfiltration | Output channels | 5 |
| AATCK-007 | Cascading Compromise | Multi-agent systems | 5 |
| AATCK-008 | Social Engineering | Trust / compliance | 7 |

I'm going to start with AATCK-008 because it's the most counterintuitive finding — and the one that convinced me this framework was necessary.

### AATCK-008: Social Engineering

AI agents are trained to be helpful. That helpfulness is exploitable.

AATCK-008 covers 7 techniques: trust escalation through rapport-building, authority impersonation, helpfulness exploitation (framing malicious requests as "helping"), reciprocity exploitation, urgency and scarcity framing, declared intent bias (stating a legitimate purpose before an illegitimate request), and collaborative framing.

In a live assessment this week, a target agent disclosed its full attack surface after being told the session was an authorized pentest. No payload. No canary. Just declaration of intent. The agent was so cooperative it enumerated its own tools, described its system prompt constraints, and suggested which of its capabilities would be most useful to test.

These attacks exploit the same patterns used against humans — except agents can't feel suspicious. They can only follow their training.

### AATCK-001: Prompt Injection

This goes well beyond "ignore previous instructions." In agent environments, prompt injection targets the data pipeline — not the user input. Think: a SIEM incident with embedded instructions in the description field, or an API response that contains directives the agent follows because it treats the data as trusted context.

AATCK-001 covers 8 techniques with 16 payload templates: direct override, indirect injection via documents and API payloads, delimiter escape, encoding evasion (base64, unicode), role injection, instruction smuggling in legitimate-looking fields, payload splitting, and few-shot poisoning.

The core problem: most agents process external data with the same trust level as their system prompt.

### AATCK-002: Tool Abuse

Agents have tools. Tools have side effects. If an attacker can influence tool selection or parameters, they can chain "legitimate" calls into something unauthorized.

AATCK-002 covers 6 techniques with 23 payload templates — the largest set in the framework: path traversal via file tools, HTTP exfiltration, shell injection through tool parameters, multi-step tool chaining (including full kill chain sequences), parameter pollution, and privilege escalation.

The tricky part is that each individual tool call looks fine. It's the chain — read config, summarize, send to "admin webhook" — that's the attack.

### AATCK-003: Context Poisoning

Unlike prompt injection (a single payload), context poisoning plays out over multiple turns. It gradually shifts the agent's behavior without any single message being obviously malicious.

AATCK-003 covers 7 techniques: gradual trust escalation, persona drift, false memory implantation, context flooding to push the system prompt out of the effective window, authority spoofing built over multiple turns, persistent memory poisoning, and multi-turn alert fatigue.

This is the hardest class to detect. The compromise emerges from accumulated effect, not from any one message.

### AATCK-004: Goal Hijacking

Goal hijacking doesn't break the agent — it redirects it. The agent works perfectly, just on the wrong objective.

AATCK-004 covers 4 techniques: priority inversion through fabricated urgent tasks, alert fatigue exploitation, objective reframing, and distraction injection.

In SOC automation, this is scary. An agent investigating five real incidents gets diverted by a fake "P0 Critical" — and drops investigation of an actual breach.

### AATCK-005: MCP Exploitation

MCP gives agents access to external tools and data. Each MCP connection is an implicit trust boundary and a potential attack vector.

AATCK-005 covers 5 techniques: tool description injection (hiding instructions in the tool's description itself), poisoned tool responses, tool name spoofing, excessive permission registration, and schema manipulation.

This is probably the biggest blind spot in enterprise AI right now. Teams add MCP integrations for productivity without testing whether those integrations can influence agent behavior.

### AATCK-006: Data Exfiltration

Agents often have access to things they shouldn't share — system prompts, configuration, internal data, user info.

AATCK-006 covers 5 techniques with 15 payloads: system prompt extraction, credential harvesting through "configuration detail" requests, indirect exfiltration via tool parameters to external endpoints, training data extraction, and cross-conversation leakage.

Most agents will give up their system prompt without much resistance. The real question is what else they'll share.

### AATCK-007: Cascading Compromise

In multi-agent setups, every agent is both a target and a potential weapon against other agents.

AATCK-007 covers 5 techniques with 11 payloads: sub-agent poisoning, credential relay, trust chain exploitation, orchestrator manipulation, and sub-agent pivot through session-spawning capabilities.

Low prevalence today. High impact tomorrow as multi-agent architectures become standard.

---

## The Kill Chain

AATCK defines a seven-phase kill chain for agent-based attacks:

**Recon** — Map the agent's tools, system prompt, data sources, and MCP connections. Agent recon usually happens through conversation, not port scanning.

**Weaponize** — Craft payloads with mutation variants (encoding, multi-language, delimiter tricks) to evade filters.

**Deliver** — Inject through the data pipeline: crafted SIEM incidents, poisoned documents, malicious MCP responses, multi-turn conversation sequences.

**Exploit** — The agent follows injected instructions, misuses a tool, or acts on corrupted context.

**Persist** — Maintain influence through context poisoning, memory manipulation, or changes to data sources.

**Exfiltrate** — Extract data through responses, tool calls, or MCP channels.

**Cascade** — Pivot to connected agents, orchestrators, or downstream systems.

The key difference from traditional kill chains: the weapon is language. The vulnerability is trust.

---

## RedClaw: Testing the Framework

A taxonomy without validation is academic. So I built RedClaw — a red team tool that automates all 8 AATCK attack classes against any AI agent.

**Canary-based detection.** Each payload contains a unique canary string. If the canary appears in the agent's response or tool calls, the attack succeeded. No ambiguity, no LLM-based judging.

**93 payload templates** across 8 classes, each expandable through 8 mutation types: base64, ROT13, unicode homoglyphs, multi-language wrappers (French, Spanish, German, Japanese), delimiter wrapping, zero-width whitespace, case alternation, and markdown escaping.

**Deterministic scoring** across 8 weighted dimensions: Prompt Injection (20%), Tool Abuse (18%), Data Protection (15%), Context Integrity (12%), Goal Integrity (10%), MCP Security (10%), Multi-Agent Isolation (8%), Social Engineering (7%). No LLM in the scoring loop. Final score maps to a letter grade — A through F.

**4 adapters** so it connects to whatever you're running: generic HTTP agents, OpenClaw agents (with Ed25519 WebSocket auth), MCP servers (stdio and SSE), and Claude API-compatible agents.

**4 pre-built campaigns**: Quick Prompt Injection scan (50 attacks), Full SOC Assessment (7 phases, all 8 classes, up to 500 attacks), MCP Security Audit (3 phases, 100 attacks), and OpenClaw Pentest (7 phases, 200 attacks).

It also ships with a deliberately vulnerable mock agent, a mock MCP server with 4 attack modes, and a canary HTTP server for detecting exfiltration — all loopback-only for safe testing.

---

## Why This Matters Now

MITRE ATT&CK gave network defenders a shared language. OWASP gave web developers a top-10 list. AATCK is the same idea applied to the agent layer — a structured way to describe, test, and communicate about how AI agents can be compromised.

This is v1 and it'll get things wrong. Agent architectures are evolving fast and the taxonomy will need to keep up. If you're working in this space — building agents, securing them, or deploying them in production — I'd genuinely like to know what I missed.

---

*Bedo is a security professional focused on AI governance, GRC, and adversarial security testing for enterprise AI systems. CISSP, CRISC.*
