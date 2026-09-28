"""AgentCore Platform v1.0 — CMN-C1-084 inline security helpers.

`framework.security` is NOT shipped in the v1.0.0 wheel, so S-2 (input) and
S-3 (output) gate primitives are implemented here in the template (the
GovernmentProcedureQAAgent pattern). These are pure functions — no I/O, no credentials.

What this module provides:
  * credential / secret literal scanning (OpenAI / JWT / AWS / generic keys)
  * lightweight PII detection + scrubbing (email, phone, JP MyNumber-ish digits)
  * input bounds (empty / oversized)

Nodes call these inside execute() to implement S-2 / S-3 inline.
"""

from __future__ import annotations

import re

# ── Credential / secret literal patterns (also caught by gate-credential-scan) ─
_CREDENTIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                 # OpenAI-style key
    re.compile(r"eyJ[A-Za-z0-9._-]{10,}"),              # JWT
    re.compile(r"AKIA[A-Z0-9]{16}"),                    # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),             # Google API key
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),        # Slack token
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # PEM private key
]

# ── PII patterns ──────────────────────────────────────────────────────────────
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Phone: international / JP style runs of digits with -, (), and spaces only
# (no ':' or 'T' — avoids matching ISO-8601 timestamps). >= 9 digits.
_PHONE = re.compile(r"(?<![\d:T=])(?:\+?\d[\d\-\s().]{7,}\d)(?![\d:T])")
# JP MyNumber-like: a bare 12-digit run.
_MYNUMBER = re.compile(r"(?<!\d)\d{12}(?!\d)")

MAX_INPUT_CHARS = 4000


class InputValidationError(ValueError):
    """Raised by S-2 input gate on empty / oversized input."""


def contains_credential(text: str) -> bool:
    """True if `text` contains a recognizable secret/credential literal."""
    if not text:
        return False
    return any(p.search(text) for p in _CREDENTIAL_PATTERNS)


def scrub_pii(text: str) -> str:
    """Mask PII (email / phone / MyNumber-like) before logging or LLM send.

    Returns a copy with PII replaced by typed placeholders. Never raises.
    """
    if not text:
        return text
    text = _EMAIL.sub("[EMAIL]", text)
    text = _MYNUMBER.sub("[ID-NUMBER]", text)
    text = _PHONE.sub("[PHONE]", text)
    return text


def contains_pii(text: str) -> bool:
    """True if `text` looks like it carries PII."""
    if not text:
        return False
    return bool(_EMAIL.search(text) or _MYNUMBER.search(text) or _PHONE.search(text))


def validate_input_bounds(text: str) -> str:
    """S-2 bounds check. Returns the stripped query or raises InputValidationError."""
    if text is None or not text.strip():
        raise InputValidationError("input is empty or whitespace-only")
    stripped = text.strip()
    if len(stripped) > MAX_INPUT_CHARS:
        raise InputValidationError(
            f"input exceeds {MAX_INPUT_CHARS} chars (got {len(stripped)})"
        )
    return stripped


def apply_output_gate(text: str) -> str:
    """S-3 content-safety scrub for the output string.

    Removes credential literals (defense in depth — they must never reach the
    caller) and masks PII. Pure transform; raising is the node's responsibility
    for citation-integrity failures.
    """
    if not text:
        return text
    for p in _CREDENTIAL_PATTERNS:
        text = p.sub("[REDACTED-CREDENTIAL]", text)
    return scrub_pii(text)
