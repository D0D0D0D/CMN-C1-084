# CMN-C1-084 — Unit Tests: inline security helpers (S-2 / S-3 primitives)

import pytest

from src.security import (
    MAX_INPUT_CHARS,
    InputValidationError,
    apply_output_gate,
    contains_credential,
    contains_pii,
    scrub_pii,
    validate_input_bounds,
)


class TestCredentialScan:
    @pytest.mark.parametrize("text", [
        "sk-abcdefghijklmnopqrstuvwxyz12345",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
        "AKIAIOSFODNN7EXAMPLE",
    ])
    def test_detects_credentials(self, text):
        assert contains_credential(text) is True

    def test_clean_text(self):
        assert contains_credential("deployment approval policy") is False

    def test_output_gate_redacts_credential(self):
        out = apply_output_gate("key sk-abcdefghijklmnopqrstuvwxyz12345 here")
        assert "sk-" not in out
        assert "[REDACTED-CREDENTIAL]" in out


class TestPII:
    def test_email_scrubbed(self):
        assert scrub_pii("user@example.com") == "[EMAIL]"

    def test_phone_scrubbed(self):
        assert "[PHONE]" in scrub_pii("call +81-90-1234-5678")

    def test_mynumber_scrubbed(self):
        assert "[ID-NUMBER]" in scrub_pii("id 123456789012")

    def test_iso_timestamp_not_scrubbed(self):
        ts = "fetched_at=2024-06-17T04:54:23.123456+00:00"
        assert scrub_pii(ts) == ts

    def test_url_not_scrubbed(self):
        url = "https://www.fsa.go.jp/2024/page"
        assert scrub_pii(url) == url

    def test_contains_pii(self):
        assert contains_pii("user@example.com") is True
        assert contains_pii("deployment policy") is False


class TestInputBounds:
    def test_empty_rejected(self):
        with pytest.raises(InputValidationError):
            validate_input_bounds("   ")

    def test_oversized_rejected(self):
        with pytest.raises(InputValidationError):
            validate_input_bounds("a" * (MAX_INPUT_CHARS + 1))

    def test_valid_stripped(self):
        assert validate_input_bounds("  hello  ") == "hello"
