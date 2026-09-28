"""AgentCore Platform v1.0 — CMN-C1-084 LLM client seam.

`framework.llm` is NOT shipped in the v1.0.0 wheel, so the template owns the
LLM abstraction (the GovernmentProcedureQAAgent pattern). This is an injection seam:

  * production wires a real provider client (key fetched via
    `ctx.secrets.require(...)` — never `os.environ`),
  * tests inject a deterministic stub.

The default implementation is offline-safe: it composes a cited answer purely
from the fetched context, so the agent is runnable and testable without any
network or API key (the S-3 gate still enforces citation integrity downstream).
"""

from __future__ import annotations

from typing import Any, Protocol


class LLMClient(Protocol):
    """Minimal generate interface used by AnswerGenerateStep."""

    def generate(
        self,
        *,
        query: str,
        context: list[dict[str, Any]],
        risk_label: str,
        temperature: float = 0.0,
    ) -> str:
        ...


class ContextGroundedLLMClient:
    """Offline-safe default: answers strictly from the fetched context.

    Citation-mandatory: appends a `Sources:` block listing each context entry's
    url + fetched_at so the S-3 citation re-verification gate can confirm every
    citation is real (present in fetched_context and on the allowlist).
    Never fabricates URLs — it only cites what was actually fetched.
    """

    def generate(
        self,
        *,
        query: str,
        context: list[dict[str, Any]],
        risk_label: str,
        temperature: float = 0.0,
    ) -> str:
        if not context:
            # No grounding available — caller is expected to use the
            # no_sources_available fallback instead of asking us to answer.
            return ""

        excerpts = "\n".join(
            f"- {c.get('excerpt', '').strip()}" for c in context if c.get("excerpt")
        )
        sources = "\n".join(
            f"[{i + 1}] {c.get('url')} (fetched_at={c.get('fetched_at')})"
            for i, c in enumerate(context)
        )
        body = (
            f"Based on the current governance sources, here is guidance for: "
            f"{query.strip()}\n\n{excerpts}\n\n"
            f"Risk level of this activity: {risk_label}."
        )
        return f"{body}\n\nSources:\n{sources}"
