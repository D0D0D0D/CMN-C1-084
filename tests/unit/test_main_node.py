# CMN-C1-084 — Unit Tests: MainNode (live-fetch orchestration)

import inspect

from framework.schemas.agent_status import AgentStatus
from src.nodes.main_node import MainNode, NO_SOURCES_MARKER
from src.services.web_fetch_service import WebFetchService

PUBLIC_IP = "93.184.216.34"
ENTRIES = [
    {"url": "https://www.fsa.go.jp/policy", "title": "FSA", "topics": ["compliance", "deployment"]},
]


def _svc(fetcher):
    return WebFetchService(
        allowlist=["www.fsa.go.jp"], fetcher=fetcher, resolver=lambda h: [PUBLIC_IP]
    )


def _ok_fetch(url, ip):
    return {"status": 200, "content_type": "text/html",
            "body": "<p>Deployment requires CISO approval.</p>", "location": ""}


class TestMainNode:
    def test_success_path_produces_cited_draft(self):
        node = MainNode(web_fetch_service=_svc(_ok_fetch), allowlist_entries=ENTRIES)
        state = {"validated_input": "deploy autonomous agent to production?",
                 "topic": "deployment", "node_history": [], "error_log": []}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["fetched_context"], "should have fetched evidence"
        assert "https://www.fsa.go.jp/policy" in result["draft_answer"]
        assert result["risk_label"] == "high"  # 'deploy'/'production'/'autonomous'
        # F-2: success path must NOT signal the no-source fallback.
        assert result["no_sources_available"] is False

    def test_no_configured_source_for_topic_falls_back(self):
        node = MainNode(web_fetch_service=_svc(_ok_fetch), allowlist_entries=ENTRIES)
        state = {"validated_input": "data retention?", "topic": "data",
                 "node_history": [], "error_log": []}
        result = node.execute(state)
        # ENTRIES has no 'data' topic → safe fallback, not error
        assert result["status"] == AgentStatus.SUCCESS.value
        assert NO_SOURCES_MARKER in result["draft_answer"]
        assert result["fetched_context"] == []
        # F-2: fallback sets the structured flag S-3 actually trusts.
        assert result["no_sources_available"] is True

    def test_transient_failure_retries_and_increments_retry_count(self):
        def failing(url, ip):
            raise TimeoutError("timeout")
        node = MainNode(web_fetch_service=_svc(failing), allowlist_entries=ENTRIES)
        state = {"validated_input": "deployment policy?", "topic": "deployment",
                 "retry_count": 0, "node_history": [], "error_log": []}
        result = node.execute(state)
        assert result["status"] == AgentStatus.RETRY.value
        assert result["retry_count"] == 1  # node increments (route does not)

    def test_retry_exhausted_falls_back(self):
        def failing(url, ip):
            raise TimeoutError("timeout")
        node = MainNode(web_fetch_service=_svc(failing), allowlist_entries=ENTRIES)
        state = {"validated_input": "deployment policy?", "topic": "deployment",
                 "retry_count": 3, "node_history": [], "error_log": []}
        result = node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert NO_SOURCES_MARKER in result["draft_answer"]

    def test_execute_method_signature(self):
        """node contract: Node implements execute(state), not _invoke_impl."""
        assert hasattr(MainNode, "execute")
        sig = inspect.signature(MainNode.execute)
        params = list(sig.parameters.keys())
        assert params[1] == "state"
        assert "_invoke_impl" not in MainNode.__dict__
