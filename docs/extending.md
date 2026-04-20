# Extending RedClaw

RedClaw has three extension points. Each uses a registry so you can add new
behavior without editing the engine or CLI:

| Extend             | Registry                                        | How to add           |
|--------------------|-------------------------------------------------|----------------------|
| Target adapter     | `redclaw.adapters.base._ADAPTER_REGISTRY`       | `@register_adapter`  |
| Attack module      | `redclaw.core.scheduler._MODULE_REGISTRY`       | `register_module()`  |
| AATCK class        | `redclaw.scoring.aatck.AATCK_REGISTRY`          | Append dataclass     |

---

## 1. Adding a new adapter

An adapter knows how to talk to one kind of target (HTTP endpoint, MCP server,
raw Claude API, …) and returns `AgentResponse` objects that attack modules can
reason about uniformly.

### Minimum implementation

```python
# redclaw/adapters/my_service.py
from __future__ import annotations

from typing import Any

from redclaw.adapters.base import AgentAdapter, AgentResponse, register_adapter
from redclaw.config import TargetConfig


@register_adapter("my_service")
class MyServiceAdapter(AgentAdapter):
    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._client: Any = None

    @property
    def adapter_type(self) -> str:
        return "my_service"

    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...

    async def send_message(self, message: str) -> AgentResponse:
        # Call your service, return a normalized AgentResponse.
        return AgentResponse(text="...")

    async def get_available_tools(self) -> list[dict[str, Any]]:
        return []
```

Two more steps to wire it in:

1. **Expose the identifier** — add `MY_SERVICE = "my_service"` to the
   `AdapterType` enum in [redclaw/config.py](../redclaw/config.py). The string
   must match the decorator argument.
2. **Register at import time** — import the new module from
   [redclaw/adapters/\_\_init\_\_.py](../redclaw/adapters/__init__.py) so the
   decorator runs when users `import redclaw`. Wrap optional dependencies in
   `contextlib.suppress(ImportError)` if your adapter needs an extras-only
   package.

Once both are done, `CampaignEngine` resolves the adapter via
`get_adapter(target.adapter.value, target)` — no engine edits required.

### Tests

Add a test under `tests/test_adapters/`. For HTTP-style adapters prefer
`httpx.MockTransport` over live servers — see
[test_http_adapter_responses.py](../tests/test_adapters/test_http_adapter_responses.py)
for the pattern.

---

## 2. Adding a new attack module

An attack module generates payloads, runs them through an adapter, and returns
`AttackResult` objects the scorer can grade.

```python
# redclaw/attacks/my_attack.py
from __future__ import annotations

from redclaw.adapters.base import AgentAdapter
from redclaw.attacks.base import (
    AttackModule,
    AttackResult,
    AttackStatus,
    Payload,
    Severity,
)
from redclaw.config import TargetConfig


class MyAttackModule(AttackModule):
    @property
    def name(self) -> str:
        return "My Attack"

    @property
    def aatck_ids(self) -> list[str]:
        return ["AATCK-001"]  # One or more AATCK class IDs

    @property
    def description(self) -> str:
        return "Describe what this module probes."

    def payloads(self) -> list[Payload]:
        return [
            Payload(
                content="your adversarial input",
                technique_id="AATCK-001.T01",
                description="Short technique name",
            ),
        ]

    async def execute(
        self,
        adapter: AgentAdapter,
        target_config: TargetConfig,
    ) -> list[AttackResult]:
        results: list[AttackResult] = []
        for p in self.payloads():
            resp = await adapter.send_message(p.content)
            results.append(
                AttackResult(
                    module_name="my_attack",
                    aatck_id="AATCK-001",
                    technique_id=p.technique_id,
                    technique_name=p.description,
                    status=AttackStatus.SUCCESS if "compromised" in resp.text else AttackStatus.DEFENDED,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    payload_used=p.content,
                    evidence=resp.text[:500],
                )
            )
        return results
```

Register the module in
[redclaw/core/scheduler.py](../redclaw/core/scheduler.py) inside
`_register_builtins()`:

```python
from redclaw.attacks.my_attack import MyAttackModule
register_module("my_attack", MyAttackModule)
```

The CLI picks the new identifier up automatically (`redclaw attacks list`).

### Canary tokens

Use `self.generate_canary()` to create a unique marker string, embed it in the
payload, and set `canary_detected=True` on the result if it appears in the
response. Scoring treats canary detection as definitive evidence of compromise.

---

## 3. Adding a new AATCK class

AATCK classes are the taxonomy attacks map onto. They live in
[redclaw/scoring/aatck.py](../redclaw/scoring/aatck.py) as frozen dataclasses.

```python
AATCK_009 = AATCKClass(
    id="AATCK-009",
    name="Your Class Name",
    description="One-sentence description of what this probes.",
    severity_range=(Severity.MEDIUM, Severity.CRITICAL),
    target="What subsystem / boundary this class targets",
    techniques=(
        Technique("AATCK-009.T01", "Technique One", "How it works."),
        Technique("AATCK-009.T02", "Technique Two", "..."),
    ),
    detection=("Signals that indicate this class fired",),
    remediation=("Mitigations an agent owner should apply",),
)
```

Append the new class to the tuple inside `AATCK_REGISTRY`. Attack modules can
then list the ID in their `aatck_ids` property and the scorer will pick it up.

Keep `docs/AATCK_FRAMEWORK.md` in sync so users see the new class in the
rendered framework doc.

---

## Verification checklist

After adding an extension, confirm it's reachable end-to-end:

```bash
# Adapter: listed by the registry
python -c "from redclaw import list_adapters; print(list_adapters())"

# Attack: listed by the CLI
redclaw attacks list

# Scoring: the new AATCK ID is grade-able
python -c "from redclaw.scoring.aatck import AATCK_REGISTRY; print(sorted(AATCK_REGISTRY))"

# Tests + coverage gate still green
pytest
```
