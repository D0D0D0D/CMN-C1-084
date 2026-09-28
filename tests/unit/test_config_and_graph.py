# CMN-C1-084 — Unit Tests: config_loader fallback parser + graph alias

from src.services.config_loader import _parse_allowlist_fallback
from src.graph.graph import Graph
from src.agent import GovernancePolicyQAAgent
from framework.graph.agent_base_graph import AgentBaseGraph


class TestFallbackParser:
    def test_parses_list_of_dicts(self):
        text = """\
agent:
  source_allowlist:
    - url: "https://www.fsa.go.jp/policy/"
      title: "FSA"
      topics: ["compliance", "risk"]
    - url: "https://www.iso.org/standard/81230.html"
      title: "ISO"
      topics: ["all"]
  required_trust_level: "VERIFIED_EXTERNAL"
"""
        entries = _parse_allowlist_fallback(text)
        assert len(entries) == 2
        assert entries[0]["url"] == "https://www.fsa.go.jp/policy/"
        assert entries[0]["topics"] == ["compliance", "risk"]
        assert entries[1]["topics"] == ["all"]

    def test_empty_inline_list(self):
        assert _parse_allowlist_fallback("source_allowlist: []\n") == []


class TestGraphAlias:
    def test_graph_is_l1_agent(self):
        # gate-composition / gate-import-isolation: src has an AgentBaseGraph subclass.
        assert issubclass(Graph, GovernancePolicyQAAgent)
        assert issubclass(Graph, AgentBaseGraph)

    def test_graph_compiles(self):
        # Graph inherits register_nodes from the agent → compiles to the backbone.
        g = Graph()
        g.compile()
        assert set(["pre_process", "main", "post_process"]).issubset(g._nodes.keys())
        assert g._nodes["main"] is not None
