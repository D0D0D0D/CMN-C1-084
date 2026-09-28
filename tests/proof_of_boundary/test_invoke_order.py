# PB-6: Invoke execution order + PB-2 runtime State serialization.
# Verifies the fixed 5-node backbone executes in order via the real framework
# invoke() (no override of __call__/route), and that the resulting State carries
# only msgpack-safe primitives.

import json

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.agent import GovernancePolicyQAAgent
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.services.web_fetch_service import WebFetchService

PUBLIC_IP = "93.184.216.34"
ENTRIES = [{"url": "https://www.fsa.go.jp/policy", "title": "FSA", "topics": ["all"]}]


def _ok(url, ip):
    return {"status": 200, "content_type": "text/html", "body": "<p>policy text</p>", "location": ""}


def _agent():
    svc = WebFetchService(allowlist=["www.fsa.go.jp"], fetcher=_ok,
                          resolver=lambda h: [PUBLIC_IP])
    main = MainNode(web_fetch_service=svc, allowlist_entries=ENTRIES)

    class _A(GovernancePolicyQAAgent):
        def register_nodes(self):
            super(GovernancePolicyQAAgent, self).register_nodes()
            self._nodes["pre_process"] = PreProcessNode()
            self._nodes["main"] = main
            self._nodes["post_process"] = PostProcessNode()

    a = _A()
    a.compile()
    return a


class TestInvokeOrder:
    def test_backbone_order(self):
        """PB-6: pre_process → main → post_process within the fixed backbone."""
        out = _agent().invoke(
            "deployment approval policy?",
            ctx=InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
        )
        hist = out["node_history"]
        assert hist == ["InitializeNode", "PreProcessNode", "MainNode",
                        "PostProcessNode", "FinalizeNode"]
        # post_process strictly after main (no reordering / no bypass)
        assert hist.index("MainNode") < hist.index("PostProcessNode")

    def test_state_is_json_serializable(self):
        """PB-2: post-invoke output contains only JSON/msgpack-safe primitives.

        msgpack is not installed in the dev image; JSON serialization (no
        default= coercion) is an equivalent 'primitives only' check — it raises
        TypeError if any Pydantic/dataclass/datetime object leaked into output.
        """
        out = _agent().invoke(
            "deployment approval policy?",
            ctx=InvocationContext(caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
        )
        encoded = json.dumps(out)  # raises TypeError on non-serializable objects
        assert isinstance(encoded, str)
