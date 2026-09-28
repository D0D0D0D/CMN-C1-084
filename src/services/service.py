"""AgentCore Platform v1.0 — CMN-C1-084 governance Q&A domain service steps.

Pure domain logic for the main-internal orchestration (docs/02_design.md §main):
SourceSelect → RiskClassify → topic classification. No routing, no credentials,
no framework imports. Nodes call these; the WebFetchService owns network/SSRF.
"""

from __future__ import annotations

from typing import Any

# Governance topic vocabulary (docs/02_design.md State 定義: topic field).
TOPICS = ("deployment", "access", "risk", "data", "compliance")

# Keyword signals per topic for the lightweight classifier.
_TOPIC_KEYWORDS: dict[str, tuple[str, ...]] = {
    "deployment": ("deploy", "release", "rollout", "production", "promote", "ship"),
    "access": ("access", "permission", "role", "rbac", "auth", "credential", "privilege"),
    "risk": ("risk", "incident", "impact", "severity", "harm", "safety", "autonomous"),
    "data": ("data", "pii", "privacy", "retention", "dataset", "personal"),
    "compliance": ("compliance", "policy", "regulation", "audit", "iso", "ismap", "fsa", "law", "control"),
}

# Activity risk signals (docs/02_design.md: risk_label low/medium/high).
_HIGH_RISK = ("autonomous", "production", "irreversible", "delete", "deploy", "payment", "customer data")
_MED_RISK = ("access", "permission", "external", "third-party", "pii", "data")


def classify_topic(query: str) -> str:
    """Classify the query into a governance topic. Defaults to 'compliance'."""
    q = (query or "").lower()
    best_topic = "compliance"
    best_score = 0
    for topic, keywords in _TOPIC_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in q)
        if score > best_score:
            best_topic = topic
            best_score = score
    return best_topic


def select_sources(
    topic: str, allowlist_entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Filter the configured allowlist entries by topic.

    allowlist_entries: [{url, title, topics: [...]}] from config/agent.yaml.
    Entries with no topic tag (or topic 'all') are always eligible.
    """
    selected: list[dict[str, Any]] = []
    for entry in allowlist_entries or []:
        topics = [t.lower() for t in entry.get("topics", [])]
        if not topics or "all" in topics or topic in topics:
            selected.append(
                {
                    "url": entry["url"],
                    "title": entry.get("title", entry["url"]),
                    "topic": topic,
                }
            )
    return selected


def classify_risk(query: str) -> str:
    """Classify the activity risk of the query: low / medium / high."""
    q = (query or "").lower()
    if any(sig in q for sig in _HIGH_RISK):
        return "high"
    if any(sig in q for sig in _MED_RISK):
        return "medium"
    return "low"
