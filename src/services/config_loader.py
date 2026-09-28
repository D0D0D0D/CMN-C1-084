"""AgentCore Platform v1.0 — CMN-C1-084 runtime config loader.

Nodes receive only `state` in execute() (1.0.0 contract), so the source allowlist
must be loaded at node construction time rather than threaded through config.
The root-level AgentRegistry manifest lives in `config/agent.yaml`, while runtime
parameters such as `source_allowlist` live in `config/config.yaml`. Loading runtime
parameters from the manifest would leave the allowlist empty and disable all sources.
この loader は YAML 依存なしで読めるよう小さな shape を前提にしている。
"""

from __future__ import annotations

import os
from typing import Any

_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "config.yaml",
)


def load_source_allowlist(path: str | None = None) -> list[dict[str, Any]]:
    """Load `source_allowlist` entries from config/config.yaml.

    Returns a list of {url, title?, topics?: [...]}. Uses PyYAML when present;
    otherwise falls back to a minimal indentation-aware parser for the
    allowlist block only. Never raises on a missing file (returns []).
    """
    path = path or _CONFIG_PATH
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        text = f.read()

    try:  # prefer PyYAML if it happens to be installed
        import yaml  # type: ignore

        data = yaml.safe_load(text) or {}
        # root-level（config.yaml の正） を優先し、旧 `agent:` ネストにも後方互換で対応する
        entries = data.get("source_allowlist")
        if entries is None:
            entries = (data.get("agent") or {}).get("source_allowlist")
        entries = entries or []
        return [_normalize_entry(e) for e in entries if _normalize_entry(e)]
    except Exception:
        return _parse_allowlist_fallback(text)


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, str):
        return {"url": entry, "title": entry, "topics": []}
    if isinstance(entry, dict) and entry.get("url"):
        return {
            "url": entry["url"],
            "title": entry.get("title", entry["url"]),
            "topics": list(entry.get("topics", [])),
        }
    return None


def _parse_allowlist_fallback(text: str) -> list[dict[str, Any]]:
    """Minimal parser for the `source_allowlist:` list-of-dicts block."""
    lines = text.splitlines()
    entries: list[dict[str, Any]] = []
    in_block = False
    block_indent = 0
    current: dict[str, Any] | None = None

    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if stripped.startswith("source_allowlist:"):
            in_block = True
            block_indent = indent
            # inline empty list: `source_allowlist: []`
            if stripped.endswith("[]"):
                in_block = False
            continue

        if in_block:
            if indent <= block_indent and not stripped.startswith("-"):
                break  # left the block
            if stripped.startswith("- "):
                if current:
                    entries.append(current)
                current = {"topics": []}
                stripped = stripped[2:].strip()
            if current is not None and ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key == "topics":
                    val_inner = val.strip("[]")
                    current["topics"] = [
                        v.strip().strip('"').strip("'")
                        for v in val_inner.split(",")
                        if v.strip()
                    ]
                elif key in ("url", "title"):
                    current[key] = val
    if current and current.get("url"):
        entries.append(current)
    return [e for e in entries if e.get("url")]
