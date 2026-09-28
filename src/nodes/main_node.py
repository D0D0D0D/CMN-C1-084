"""AgentCore Platform v1.0 — CMN-C1-084 MainNode (live-fetch orchestration)."""

# Node contract (v1.0):
#  - Extend FunctionNode; implement execute(self, state) -> dict
#  - Return ONLY changed keys (never full state, never node_history)
#  - Return AgentStatus VALUES (small-case strings)
#
# main is a SINGLE backbone node that orchestrates the live-fetch sub-steps in
# plain Python (no extra graph nodes) — Cat 1 fixed 5-node backbone (docs/02
# §main). Sub-steps: SourceSelect → WebFetchAndExtract → RiskClassify →
# AnswerGenerate.
#
# Retry: transient fetch failure → status=retry. Because the framework's route()
# does NOT auto-increment retry_count, this node increments it when returning
# RETRY so the pre_process retry loop terminates at max_retry.
#
# Exhaustion fallback: if no source could be fetched after retries, return a
# safe "no current information" answer carrying the no_sources_available marker
# (S-3 exempts it from the citation-mandatory check — never fabricate).

from __future__ import annotations

from typing import Any, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

from src.services.config_loader import load_source_allowlist
from src.services.http_transport import default_http_fetch
from src.services.llm_client import ContextGroundedLLMClient, LLMClient
from src.services.service import classify_risk, select_sources
from src.services.web_fetch_service import WebFetchService

# Marker placed in `result` when all sources were unreachable (S-3 whitelist).
NO_SOURCES_MARKER = "no_sources_available"
_FALLBACK_ANSWER = (
    "I could not retrieve current governance sources to answer this question "
    "reliably right now. Please retry shortly or consult the governance team. "
    f"[{NO_SOURCES_MARKER}]"
)


class MainNode(FunctionNode):
    """Orchestrates SourceSelect → WebFetch → RiskClassify → AnswerGenerate."""

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(
        self,
        web_fetch_service: Optional[WebFetchService] = None,
        llm_client: Optional[LLMClient] = None,
        allowlist_entries: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        # allowlist host set drives the WebFetchService gate; entries (with
        # topics) drive SourceSelect.
        self._allowlist_entries = (
            allowlist_entries if allowlist_entries is not None else load_source_allowlist()
        )
        hosts = self._allowlist_hosts(self._allowlist_entries)
        self._svc = web_fetch_service or WebFetchService(
            allowlist=hosts, fetcher=default_http_fetch
        )
        self._llm = llm_client or ContextGroundedLLMClient()

    @staticmethod
    def _allowlist_hosts(entries: list[dict[str, Any]]) -> list[str]:
        from urllib.parse import urlparse

        hosts = []
        for e in entries:
            host = urlparse(e.get("url", "")).hostname
            if host:
                hosts.append(host)
        return hosts

    def execute(self, state: dict) -> dict:
        # S-4: emit at least one domain event on every execution path,
        # including the upstream-error pass-through below.
        emit_trace_event(
            "governance_qa.main_start",
            {"topic": state.get("topic", "compliance"), "upstream_error": state.get("status") == AgentStatus.ERROR.value},
            state,
        )

        # ── Upstream-error pass-through ───────────────────────────────────
        # pre_process → main is an UNCONDITIONAL backbone edge (route() runs
        # only AFTER main). If S-1/S-2 already failed upstream, do not fetch —
        # pass the error status through so route() sends it to finalize
        # (see docs/02_design.md §Error ルート).
        if state.get("status") == AgentStatus.ERROR.value:
            return {"status": AgentStatus.ERROR.value}

        query = state.get("validated_input") or state.get("user_input", "")
        topic = state.get("topic", "compliance")

        # ── 1. SourceSelect (topic-filtered allowlist) ────────────────────
        selected = select_sources(topic, self._allowlist_entries)
        risk_label = classify_risk(query)

        if not selected:
            # No configured sources for this topic — safe fallback, not an error.
            return self._fallback(risk_label, "no sources configured for topic")

        # ── 2. WebFetchAndExtract (allowlist + SSRF enforced in service) ──
        urls = [s["url"] for s in selected]
        fetched, transient = self._svc.fetch_many(urls)

        if not fetched:
            # All sources unreachable. If failures were transient, RETRY (bounded);
            # otherwise fall back safely. retry_count is incremented here because
            # route() does not auto-increment it.
            retry_count = state.get("retry_count", 0)
            max_retry = 3
            # Emit RETRY only while route() will still re-route — route() re-routes
            # when the NEW retry_count (retry_count + 1) is < max_retry. Otherwise
            # this is the final attempt → fall back now (avoids ending on RETRY).
            if transient and (retry_count + 1) < max_retry:
                return {
                    "selected_sources": selected,
                    "fetched_context": [],
                    "risk_label": risk_label,
                    "status": AgentStatus.RETRY.value,
                    "retry_count": retry_count + 1,
                    "error_log": [f"MainNode: transient fetch failure: {transient}"],
                }
            return self._fallback(
                risk_label, f"all sources unreachable: {transient}", selected
            )

        # ── 3. RiskClassify (already computed) + 4. AnswerGenerate ────────
        draft = self._llm.generate(
            query=query, context=fetched, risk_label=risk_label, temperature=0.0
        )

        return {
            "selected_sources": selected,
            "fetched_context": fetched,
            "risk_label": risk_label,
            "draft_answer": draft,
            # Sources WERE fetched — never the fallback path. Set the flag
            # explicitly so a stale True from a prior retry cannot leak through.
            "no_sources_available": False,
            "status": AgentStatus.SUCCESS.value,
        }

    def _fallback(
        self,
        risk_label: str,
        reason: str,
        selected: Optional[list[dict[str, Any]]] = None,
    ) -> dict:
        """Safe, citation-free fallback.

        Sets the structured ``no_sources_available`` state flag (NOT just the
        marker string in the answer text) — this flag is the ONLY thing S-3
        trusts to exempt the citation-mandatory check (F-2). fetched_context is
        empty here, which S-3 also requires for the exemption.
        """
        return {
            "selected_sources": selected or [],
            "fetched_context": [],
            "risk_label": risk_label,
            "draft_answer": _FALLBACK_ANSWER,
            "no_sources_available": True,
            "status": AgentStatus.SUCCESS.value,
            "error_log": [f"MainNode: fallback ({reason})"],
        }
