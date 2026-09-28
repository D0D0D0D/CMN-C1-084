# CMN-C1-084 — Unit Tests: domain service steps + config loader

from src.services.config_loader import load_source_allowlist
from src.services.service import classify_risk, classify_topic, select_sources


class TestTopicClassify:
    def test_deployment(self):
        assert classify_topic("how do I deploy to production?") == "deployment"

    def test_access(self):
        assert classify_topic("what RBAC permission is needed?") == "access"

    def test_default_compliance(self):
        assert classify_topic("general policy question") == "compliance"


class TestRiskClassify:
    def test_high(self):
        assert classify_risk("deploy autonomous agent to production") == "high"

    def test_medium(self):
        assert classify_risk("grant external access to data") == "medium"

    def test_low(self):
        assert classify_risk("what is the documentation style guide?") == "low"


class TestSourceSelect:
    ENTRIES = [
        {"url": "https://a/x", "title": "A", "topics": ["deployment"]},
        {"url": "https://b/y", "title": "B", "topics": ["data"]},
        {"url": "https://c/z", "title": "C", "topics": ["all"]},
    ]

    def test_topic_filter(self):
        sel = select_sources("deployment", self.ENTRIES)
        urls = {s["url"] for s in sel}
        assert urls == {"https://a/x", "https://c/z"}  # deployment + all

    def test_no_match_returns_only_all(self):
        sel = select_sources("compliance", self.ENTRIES)
        assert {s["url"] for s in sel} == {"https://c/z"}


class TestConfigLoader:
    def test_loads_real_agent_yaml_allowlist(self):
        entries = load_source_allowlist()
        # config/agent.yaml ships 4 curated entries
        assert len(entries) >= 1
        assert all("url" in e for e in entries)
        urls = " ".join(e["url"] for e in entries)
        assert "fsa.go.jp" in urls

    def test_missing_file_returns_empty(self):
        assert load_source_allowlist("/nonexistent/agent.yaml") == []
