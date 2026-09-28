# CMN-C1-084 — Integration Tests: full backbone via agent.invoke()
# Uses an injected WebFetchService (stub fetcher+resolver) — NO real network.

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.agent import GovernancePolicyQAAgent
from src.nodes.main_node import MainNode, NO_SOURCES_MARKER
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.services.web_fetch_service import WebFetchService

PUBLIC_IP = "93.184.216.34"
ENTRIES = [
    {"url": "https://www.fsa.go.jp/policy", "title": "FSA", "topics": ["compliance", "deployment"]},
]


def _build_agent(fetcher):
    svc = WebFetchService(allowlist=["www.fsa.go.jp"], fetcher=fetcher,
                          resolver=lambda h: [PUBLIC_IP])
    main = MainNode(web_fetch_service=svc, allowlist_entries=ENTRIES)

    class _Agent(GovernancePolicyQAAgent):
        def register_nodes(self):
            # call AgentBaseGraph.register_nodes (inject init/finalize)
            super(GovernancePolicyQAAgent, self).register_nodes()
            self._nodes["pre_process"] = PreProcessNode()
            self._nodes["main"] = main
            self._nodes["post_process"] = PostProcessNode()

    agent = _Agent()
    agent.compile()
    return agent


def _ctx(trust=TrustLevel.VERIFIED_EXTERNAL):
    return InvocationContext(caller_trust_level=trust)


class TestFullBackbone:
    def test_happy_path_all_five_nodes(self):
        def ok(url, ip):
            return {"status": 200, "content_type": "text/html",
                    "body": "<p>Deployment requires CISO approval.</p>", "location": ""}
        agent = _build_agent(ok)
        out = agent.invoke("What approval is required to deploy an autonomous agent to production?",
                           ctx=_ctx())
        assert out["status"] == AgentStatus.SUCCESS.value
        assert out["node_history"] == [
            "InitializeNode", "PreProcessNode", "MainNode", "PostProcessNode", "FinalizeNode"
        ]
        assert "fsa.go.jp" in str(out["output"])
        assert "risk_label" in str(out["output"])

    def test_all_sources_unreachable_returns_safe_fallback(self):
        def failing(url, ip):
            raise TimeoutError("timeout")
        agent = _build_agent(failing)
        out = agent.invoke("deployment policy for production agents?", ctx=_ctx())
        # retries then falls back; final answer is the safe no-info answer, never fabricated.
        assert out["status"] == AgentStatus.SUCCESS.value
        assert NO_SOURCES_MARKER in str(out["output"])

    def test_empty_input_blocked_at_pre_process(self):
        fetch_calls = []

        def counting(url, ip):
            fetch_calls.append(url)
            return {"status": 200, "content_type": "text/html", "body": "<p>x</p>", "location": ""}
        agent = _build_agent(counting)
        out = agent.invoke("   ", ctx=_ctx())
        # S-2 rejects → status ERROR. main is on an UNCONDITIONAL backbone edge so
        # it still runs, but it passes the error through and performs NO fetch.
        assert out["status"] == AgentStatus.ERROR.value
        assert fetch_calls == []                 # main short-circuited — no fetch
        assert not out.get("output")             # no fabricated answer


class TestS1TrustGate:
    def test_anonymous_caller_denied(self):
        fetch_calls = []

        def counting(url, ip):
            fetch_calls.append(url)
            return {"status": 200, "content_type": "text/html", "body": "<p>x</p>", "location": ""}
        agent = _build_agent(counting)
        out = agent.invoke("deployment policy?", ctx=_ctx(trust=TrustLevel.ANONYMOUS))
        # S-1: PreProcessNode requires VERIFIED_EXTERNAL → BaseNode.__call__ trust gate
        # denies BEFORE execute() (status ERROR). main passes through; nothing is fetched.
        assert out["status"] == AgentStatus.ERROR.value
        assert fetch_calls == []          # trust gate fired before any fetch
        assert not out.get("output")      # no answer returned to an anonymous caller
        assert out["node_history"][:2] == ["InitializeNode", "PreProcessNode"]
