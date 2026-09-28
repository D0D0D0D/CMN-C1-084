# CMN-C1-084 — Unit Tests: PreProcessNode (S-2 input gate + topic classify)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.pre_process_node import PreProcessNode
from src.security import MAX_INPUT_CHARS


class TestPreProcessNode:
    def setup_method(self):
        self.node = PreProcessNode()

    def test_valid_input_classified(self):
        state = {"user_input": "What approval is required to deploy an agent?",
                 "input_context": {"channel": "ui"}, "node_history": [], "error_log": []}
        out = self.node.execute(state)
        assert out["status"] == AgentStatus.SUCCESS.value
        assert out["validated_input"]
        assert out["topic"] == "deployment"
        assert out["enriched_context"]["channel"] == "ui"

    def test_empty_input_rejected_s2(self):
        out = self.node.execute({"user_input": "   ", "input_context": {},
                                 "node_history": [], "error_log": []})
        assert out["status"] == AgentStatus.ERROR.value
        assert out["error_log"]

    def test_oversized_input_rejected_s2(self):
        out = self.node.execute({"user_input": "a" * (MAX_INPUT_CHARS + 1),
                                 "input_context": {}, "node_history": [], "error_log": []})
        assert out["status"] == AgentStatus.ERROR.value

    def test_pii_scrubbed_before_processing(self):
        out = self.node.execute({"user_input": "my email is alice@example.com, deployment policy?",
                                 "input_context": {}, "node_history": [], "error_log": []})
        assert out["status"] == AgentStatus.SUCCESS.value
        assert "alice@example.com" not in out["validated_input"]
        assert "[EMAIL]" in out["validated_input"]

    def test_trust_level_declared(self):
        assert PreProcessNode.required_trust_level == TrustLevel.VERIFIED_EXTERNAL
