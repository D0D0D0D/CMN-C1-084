"""AgentCore Platform v1.0 — CMN-C1-084 PostProcessNode (S-3 output gate + S-4)."""

# Node contract (v1.0): execute(self, state) -> dict, return changed keys only,
# return AgentStatus VALUES (small-case strings).
#
# S-3 output gate (docs/02_design.md §セキュリティ設計):
#   1. Block claims lacking citations (url + fetched_at).
#   2. Re-verify EACH cited url actually exists in fetched_context AND belongs
#      to source_allowlist (rejects LLM-fabricated / off-allowlist citations).
#   3. Credential + PII scrub on the output.
#   4. EXEMPT the no_sources_available fallback from the citation-mandatory check
#      (so a legitimately uncited "no info" answer is not stuck in a RETRY loop).
# S-4 audit: emit_trace_event with topic, source urls, fetch timestamps, risk.

from __future__ import annotations

import re
from typing import Any, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

from src.security import apply_output_gate, contains_credential
from src.services.config_loader import load_source_allowlist
from src.services.web_fetch_service import host_of

# Extract http(s) URLs cited in the draft answer.
_URL_RE = re.compile(r"https?://[^\s\)\]\"'>]+")


class PostProcessNode(FunctionNode):
    """S-3 content-safety + citation-integrity gate, then S-4 audit emit."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(
        self, allowlist_entries: Optional[list[dict[str, Any]]] = None
    ) -> None:
        # Load the *config* allowlist (config/agent.yaml) so S-3 can cross-check
        # every cited host against the OPERATOR-CURATED trust boundary — not just
        # against whatever ended up in fetched_context (F-3). Hosts are normalized
        # with the SAME function WebFetchService uses (case + trailing dot), so a
        # casing/FQDN-root mismatch cannot open a bypass.
        entries = (
            allowlist_entries
            if allowlist_entries is not None
            else load_source_allowlist()
        )
        self._config_allowlist_hosts = {
            host_of(e.get("url")) for e in entries if host_of(e.get("url"))
        }

    def execute(self, state: dict) -> dict:
        draft = state.get("draft_answer", "")
        fetched_context = state.get("fetched_context", []) or []
        risk_label = state.get("risk_label", "unknown")
        topic = state.get("topic", "")

        # ── Fallback exemption (F-2): trust the STRUCTURED state flag set by
        # MainNode, never a marker string inside the LLM-generated draft. The
        # exemption applies ONLY when main signalled the no-source fallback AND
        # no context was fetched — a prompt-injected marker cannot trigger it.
        is_fallback = bool(state.get("no_sources_available")) and not fetched_context

        # ── S-3.1/3.2 citation integrity (skipped only for the real fallback) ─
        if not is_fallback:
            fetched_hosts = {
                host_of(c.get("url")) for c in fetched_context if c.get("url")
            }
            fetched_urls = {c.get("url") for c in fetched_context if c.get("url")}

            cited = _URL_RE.findall(draft)
            if not cited or not fetched_context:
                return self._block(
                    state, "S-3: answer has no citations (url + fetched_at required)"
                )

            # every fetched_context entry must carry a fetched_at timestamp
            if any(not c.get("fetched_at") for c in fetched_context):
                return self._block(state, "S-3: fetched_context entry missing fetched_at")

            for url in cited:
                clean = url.rstrip(".,);]")
                host = host_of(clean)
                # (a) cited url must be a real fetched url (no fabrication)
                if clean not in fetched_urls:
                    return self._block(
                        state, f"S-3: fabricated citation not in fetched_context: {clean}"
                    )
                # (b) cited host must actually be in fetched_context …
                if host not in fetched_hosts:
                    return self._block(
                        state, f"S-3: citation host not in fetched_context: {host}"
                    )
                # (c) … AND on the real CONFIG allowlist (defense-in-depth: if the
                #     fetch layer were bypassed and a forbidden host reached
                #     fetched_context, S-3 still rejects it). F-3.
                if host not in self._config_allowlist_hosts:
                    return self._block(
                        state, f"S-3: citation host off config allowlist: {host}"
                    )

        # ── S-3.3 credential / PII scrub (always) ─────────────────────────
        if contains_credential(draft):
            return self._block(state, "S-3: credential literal detected in output")
        safe_output = apply_output_gate(draft)

        result = f"{safe_output}\n\n[risk_label: {risk_label}]"

        # ── S-4 audit ─────────────────────────────────────────────────────
        emit_trace_event(
            "governance_qa.answer",
            {
                "topic": topic,
                "risk_label": risk_label,
                "source_urls": [c.get("url") for c in fetched_context],
                "fetched_at": [c.get("fetched_at") for c in fetched_context],
                "fallback": is_fallback,
            },
            state,
        )

        return {
            "result": result,
            "status": AgentStatus.SUCCESS.value,
        }

    def _block(self, state: dict, reason: str) -> dict:
        """S-3 block: emit audit and return ERROR (route() → finalize)."""
        emit_trace_event(
            "governance_qa.s3_block",
            {"reason": reason, "topic": state.get("topic", "")},
            state,
        )
        return {
            "status": AgentStatus.ERROR.value,
            "error_log": [f"PostProcessNode: {reason}"],
        }
