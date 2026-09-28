"""AgentCore Platform v1.0 — CMN-C1-084 graph entry point."""

# CMN-C1-084 — AI Agent Lifecycle & Governance Policy Q&A Agent
# Cat 1 fixed pipeline — three backbone slots wired by AgentBaseGraph.
# L1 Base: AgentBaseGraph (direct L1 inheritance — no Level 2 base class).
#
# The canonical agent class lives in src/agent.py (AgentRegistry entry point,
# referenced by config/agent.yaml and src/api/server.py). `Graph` is a thin
# alias kept for backbone/convention compatibility so the graph definition has
# a single source of truth.

from __future__ import annotations

from framework.graph.agent_base_graph import AgentBaseGraph  # noqa: F401  (gate-composition marker)

from src.agent import GovernancePolicyQAAgent


class Graph(GovernancePolicyQAAgent):
    """CMN-C1-084 governance-policy Q&A pipeline (Cat 1 fixed backbone).

    Inherits register_nodes() / name / state_schema from GovernancePolicyQAAgent
    (which itself inherits AgentBaseGraph). No behavior change — alias only.
    """
