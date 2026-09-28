"""AgentCore Platform v1.0"""

# src/agent.py — Agent entry point for AgentRegistry auto-discovery.
#
# S-1 trust gate: enforced automatically by BaseNode.__call__() reading
# required_trust_level from state["caller_trust_level"] (ADR-006, security layer S-1).
# __pre_invoke__() overrides are prohibited — the framework never calls them.
#
# S-3 output gate: implemented in PostProcessNode._security_gate_output().

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.schemas.trust_level import TrustLevel
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State


class GovernancePolicyQAAgent(AgentBaseGraph):
    """CMN-C1-084 AI Agent Lifecycle & Governance Policy Q&A Agent.

    S-1: required_trust_level enforced automatically by BaseNode.__call__()
         for every node — no __pre_invoke__ override needed or permitted (ADR-006).
    S-2: _security_gate_input() implemented in PreProcessNode.
    S-3: _security_gate_output() implemented in PostProcessNode.
    S-4: _emit_trace_event() implemented in PostProcessNode.
    S-5: __init_subclass__ JWT detection — automatic (framework).
    """

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    @property
    def name(self) -> str:
        return "cmn_c1_084"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        self._nodes["pre_process"]  = PreProcessNode()
        self._nodes["main"]         = MainNode()
        self._nodes["post_process"] = PostProcessNode()

