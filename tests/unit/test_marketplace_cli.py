"""Tests for the root AGENTIC STAR Marketplace entry adapter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.base import SecretProvider
from framework.utils.config_loader import load_config

from src.agent import GovernancePolicyQAAgent
from src.services import config_loader
from src.services import web_fetch_service
from src.nodes import main_node

REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_IP = "93.184.216.34"


class RecordingProvider(SecretProvider):
    def __init__(self) -> None:
        self.requested: list[str] = []

    def get(self, key: str, default: str | None = None) -> str | None:
        self.requested.append(key)
        return default


def _load_cli() -> ModuleType:
    spec = importlib.util.spec_from_file_location("marketplace_cli", REPO_ROOT / "cli.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verified_context() -> InvocationContext:
    return InvocationContext(
        caller_id="marketplace-runner",
        caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
    )


def test_runner_order_succeeds_without_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cli = _load_cli()
    fetch_calls: list[tuple[str, str]] = []

    def fake_fetch(url: str, pinned_ip: str) -> dict[str, Any]:
        fetch_calls.append((url, pinned_ip))
        return {
            "status": 200,
            "content_type": "text/html",
            "body": "<p>Production deployment requires documented governance approval.</p>",
            "location": "",
        }

    # MainNode binds both defaults during compile(), matching runner order.
    monkeypatch.setattr(main_node, "default_http_fetch", fake_fetch)
    monkeypatch.setattr(web_fetch_service, "_default_resolver", lambda _host: [PUBLIC_IP])

    config = load_config(str(REPO_ROOT / "config" / "config.yaml"))
    agent = cli.MarketplaceGraph(config=config)
    agent.compile()
    agent.provision_secrets(RecordingProvider())
    result = agent.invoke(
        "What governance approval is required before an AI agent is deployed?",
        ctx=_verified_context(),
        input_context={"conversation_history": []},
    )

    assert result["status"] == "success"
    assert result.get("output") or result.get("result")
    assert fetch_calls


def test_input_context_is_rebuilt_and_hitl_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    cli = _load_cli()
    captured: dict[str, Any] = {}

    def capture_invoke(
        self: GovernancePolicyQAAgent,
        user_input: str,
        session_id: str = "",
        ctx: InvocationContext | None = None,
        input_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        captured.update(
            user_input=user_input,
            session_id=session_id,
            ctx=ctx,
            input_context=input_context,
        )
        return {"status": "success", "output": "captured"}

    monkeypatch.setattr(GovernancePolicyQAAgent, "invoke", capture_invoke)
    agent = cli.MarketplaceGraph(config={})
    result = agent.invoke(
        "What is the deployment policy?",
        session_id="session-1",
        ctx=_verified_context(),
        input_context={
            "conversation_history": ["unscanned text"],
            "future_runner_key": "must not pass through",
        },
    )

    assert result["status"] == "success"
    assert captured["input_context"] == {"channel": "marketplace"}
    assert captured["ctx"].hitl_allowed is False


def test_provision_secrets_fails_closed_for_missing_allowlist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli = _load_cli()
    monkeypatch.setattr(config_loader, "_CONFIG_PATH", str(tmp_path / "missing.yaml"))

    with pytest.raises(RuntimeError, match="source allowlist is empty or unreadable"):
        cli.MarketplaceGraph().provision_secrets(RecordingProvider())


def test_provision_secrets_accepts_nonempty_allowlist_without_azure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli = _load_cli()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "source_allowlist:\n  - url: https://www.fsa.go.jp/policy/\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_loader, "_CONFIG_PATH", str(config_path))
    provider = RecordingProvider()
    supplied_config = {"generation_mode": "deterministic"}

    agent = cli.MarketplaceGraph(config=supplied_config)
    agent.provision_secrets(provider)

    assert "llm" not in supplied_config
    assert "llm" not in agent.config
    assert provider.requested == []
    assert agent._secrets_provider is provider
