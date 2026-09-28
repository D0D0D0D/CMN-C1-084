"""AgentCore Platform v1.0 — CMN-C1-084 PreProcessNode (S-2 input gate)."""

# Node contract (v1.0):
#  - Extend FunctionNode; implement execute(self, state) -> dict
#  - Return ONLY the fields this node changes (never full state, no node_history)
#  - Return AgentStatus VALUES (small-case strings) — route() resolves them
#  - Read input_context via state.get("input_context", {}) — read-only
#
# Backbone mapping (docs/02_design.md):
#   QueryNormalize (S-2 input gate) + PolicyTopicClassify  → validated_input, topic

from __future__ import annotations

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

from src.security import InputValidationError, scrub_pii, validate_input_bounds
from src.services.service import classify_topic


class PreProcessNode(FunctionNode):
    """S-2 input gate, query normalization, and governance-topic classification.

    S-1: VERIFIED_EXTERNAL — enforced automatically by BaseNode.__call__()
         before execute() runs (ADR-006). Declared here for clarity/audit.
    """

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict) -> dict:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only

        # S-4: emit at least one domain event per node.
        emit_trace_event(
            "governance_qa.pre_process",
            {"input_length": len(user_input), "channel": input_context.get("channel", "unknown")},
            state,
        )

        # ── S-2 input gate: bounds (empty / oversized) ────────────────────
        try:
            normalized = validate_input_bounds(user_input)
        except InputValidationError as exc:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PreProcessNode: S-2 input gate rejected input: {exc}"],
            }

        # ── S-2: PII scrub before the query is logged / sent to the LLM ───
        sanitized = scrub_pii(normalized)

        # ── PolicyTopicClassify ───────────────────────────────────────────
        topic = classify_topic(sanitized)

        return {
            "validated_input": sanitized,
            "enriched_context": {
                "source": "cmn-c1-084",
                "channel": input_context.get("channel", "unknown"),
            },
            "topic": topic,
            "status": AgentStatus.SUCCESS.value,
        }
