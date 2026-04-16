Anthropic just announced Project Glasswing — AI that finds zero-days in operating systems, browsers, and critical infrastructure. $100M. 12 major tech partners. Real findings already patched.

It's addressing code vulnerabilities in software infrastructure. That's important.

But there's an adjacent attack surface nobody has a formal framework for: the AI agent layer.

Not the model. The agent. The system that reads your SIEM data, invokes tools, maintains context across conversations, connects to MCP servers, and sometimes delegates to other agents.

Prompt injection through data pipelines. Tool abuse chains. Context poisoning across turns. Cascading compromise in multi-agent systems. Social engineering that exploits helpfulness instead of humans.

I've spent the past few months building AATCK — an adversarial taxonomy for AI agents modeled after MITRE ATT&CK — and RedClaw, the tool that automates assessments against any agent.

Today I ran a full 8-class assessment: 93 attacks, 8 dimensions, deterministic scoring. No LLM in the scoring loop. Binary canary-based detection.

The declared intent bias finding alone is worth a separate post: an agent disclosed its full attack surface simply because the session was framed as an authorized pentest. No payload. Just words.

If you're deploying agents in production — SOC automation, customer service, code generation, governance — you should be testing them.

Article in comments. Feedback welcome.

#AIGov #Cybersecurity #RedTeam #AIAgents #AATCK
