"""Shared fixtures for live-check harnesses."""

from __future__ import annotations

import pytest


@pytest.fixture
def agent_config() -> dict:
    """The current graph constructor does not consume injected config."""
    return {}


@pytest.fixture
def case_payload() -> str:
    """`tests/integration/test_main_node_integration.py` の happy path と同じ質問文。"""
    return "What approval is required to deploy an autonomous agent to production?"


@pytest.fixture
def live_input_context() -> dict:
    """Integration tests use only optional channel metadata for preprocessing."""
    return {"channel": "live-check"}
