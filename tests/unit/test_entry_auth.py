# Entry-adapter authentication tests.
#
# Verifies the server.py _ctx() auth core:
#   - unauthenticated caller (no verified middleware trust, no token) -> 401
#     (the old fail-open default to VERIFIED_EXTERNAL is removed);
#   - Bearer INVOKE_AUTH_TOKEN promotes ANONYMOUS -> VERIFIED_EXTERNAL -> 200;
#   - a wrong Bearer token -> 401;
#   - /health stays open (no auth).
#
# Requires the framework wheel + fastapi. In environments without them the
# module is skipped at import (pytest.importorskip), so it does not turn the
# suite red; it runs green in CI/STG where the wheel is provisioned.

import pytest

pytest.importorskip("framework")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", "mock-invoke-token-for-testing")
    # Import after env is set so the module-level app picks up a clean state.
    from src.api import server

    return TestClient(server.app, raise_server_exceptions=False)


def test_health_is_open(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_invoke_without_auth_is_rejected(client):
    # No verified middleware trust and no Bearer token -> 401 (fail-closed).
    resp = client.post("/invoke", json={"input": "What is the AI governance policy?"})
    assert resp.status_code == 401


def test_invoke_with_wrong_token_is_rejected(client):
    resp = client.post(
        "/invoke",
        json={"input": "What is the AI governance policy?"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_invoke_with_valid_token_promotes_trust(client):
    # Valid Bearer token promotes ANONYMOUS -> VERIFIED_EXTERNAL; the request
    # reaches the agent (status is not an auth rejection).
    resp = client.post(
        "/invoke",
        json={"input": "What is the AI governance policy?"},
        headers={"Authorization": "Bearer mock-invoke-token-for-testing"},
    )
    assert resp.status_code not in (401, 403)
