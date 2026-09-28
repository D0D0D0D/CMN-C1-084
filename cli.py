"""AGENTIC STAR Marketplace entry adapter for CMN-C1-084."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from framework.secrets.base import SecretProvider

try:
    from framework.utils.config_loader import load_agent_config
except ImportError:  # AgentCore 1.0.0 compatibility
    from framework.utils.config_loader import load_config

    def load_agent_config(agent_dir: Path) -> dict[str, Any]:
        config_path = agent_dir / "config" / "config.yaml"
        return load_config(str(config_path)) if config_path.exists() else {}


from src.agent import GovernancePolicyQAAgent
from src.services.config_loader import load_source_allowlist

_NAMESPACE = "cmn"
_AGENT_NAME = "CMN-C1-084"
_PROVIDER_AGENT_NAME = "cmn_c1_084"


class MarketplaceGraph(GovernancePolicyQAAgent):
    """Marketplace boundary for the deterministic governance-policy agent."""

    def invoke(
        self,
        user_input: str,
        session_id: str = "",
        ctx: Any | None = None,
        input_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Runner history is untrusted free text outside this agent's S-2 scan.
        # Rebuild rather than merge so current and future runner keys cannot
        # enter State. The channel is adapter-owned and consumed for auditing.
        del input_context
        if ctx is not None:
            ctx = replace(ctx, hitl_allowed=False)
        return cast(
            dict[str, Any],
            super().invoke(
                user_input,
                session_id=session_id,
                ctx=ctx,
                input_context={"channel": "marketplace"},
            ),
        )

    def provision_secrets(self, provider: SecretProvider) -> None:
        # A missing/unreadable runtime config otherwise becomes a silent,
        # successful no-sources response for every request.
        if not load_source_allowlist():
            raise RuntimeError(
                f"{_AGENT_NAME} Marketplace startup aborted: source allowlist "
                "is empty or unreadable"
            )
        super().provision_secrets(provider)


def main() -> None:
    # Marketplace bootstrap is absent from AgentCore 1.0.0, so keep the import
    # lazy and allow this adapter module to be imported by registry/tests.
    from shared.bootstrap import run_agent_marketplace

    config = load_agent_config(Path(__file__).resolve().parent)
    run_agent_marketplace(
        MarketplaceGraph,
        agent_name=_AGENT_NAME,
        namespace=_NAMESPACE,
        config=config,
    )


if __name__ == "__main__":
    main()
