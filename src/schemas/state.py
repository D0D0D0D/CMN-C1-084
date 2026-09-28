"""AgentCore Platform v1.0 — CMN-C1-084 State (Live Web Fetch governance Q&A)."""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel / dataclass.
# LangGraph checkpoints use msgpack serialization; Pydantic objects cause silent
# corruption. Extend AgentState with agent-specific, JSON-serializable fields
# only. Do NOT add credentials, secrets, JWTs, or InvocationContext.
#
# datetime is prohibited (msgpack-unsafe) — `fetched_at` is held as an ISO-8601
# *string* (see fetched_context below).

from __future__ import annotations

from typing import Any

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """CMN-C1-084 AI Agent Lifecycle & Governance Policy Q&A state.

    All shared fields (user_input, input_context, status, session_id,
    node_history, error_log, retry_count, etc.) are inherited from AgentState.

    Live Web Fetch pipeline (docs/02_design.md §State 定義). All fields are
    primitives / JSON-serializable containers only.
    """

    # ── pre_process output ────────────────────────────────────────────────
    validated_input: str                    # sanitized governance query (after S-2)
    # enriched_context is treated as read-only AFTER pre_process. This is a
    # convention, NOT a runtime guard — downstream nodes must not mutate it.
    enriched_context: dict[str, Any]        # {source, channel}
    topic: str                              # deployment / access / risk / data / compliance

    # ── main output ───────────────────────────────────────────────────────
    selected_sources: list[dict[str, Any]]  # [{url, title, topic}] — chosen from allowlist
    # fetched_context entries: {url, fetched_at (ISO-8601 *string*), excerpt}
    fetched_context: list[dict[str, Any]]   # evidence backing the answer
    risk_label: str                         # low / medium / high (of the query activity)
    draft_answer: str                       # LLM answer BEFORE the S-3 gate
    # Structured fallback flag set by MainNode when NO source could be fetched.
    # S-3 (PostProcessNode) trusts THIS flag — never a marker string inside the
    # LLM-generated draft_answer — to exempt the citation-mandatory check, so a
    # prompt-injected draft cannot fake the exemption (F-2).
    no_sources_available: bool              # True only when main hit the safe fallback

    # ── post_process output ───────────────────────────────────────────────
    result: str                             # final cited answer + risk label (after S-3)
