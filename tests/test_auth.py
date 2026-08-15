"""Every authentication failure looks the same from outside."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pingjack.auth import DEMO_TOKENS

ALPHA_TOKEN = "demo-token-alpha-not-a-real-secret"  # noqa: S105 - fictional demo credential

CREDENTIAL_FAILURES: list[dict[str, str]] = [
    {},
    {"Authorization": "Bearer"},
    {"Authorization": "notbearer abc"},
    {"Authorization": "Basic YWJjOmRlZg=="},
    {"Authorization": "Bearer nope-not-a-known-token"},
]


@pytest.mark.parametrize("headers", CREDENTIAL_FAILURES)
def test_every_credential_failure_returns_the_same_generic_401(
    secure_client: TestClient, headers: dict[str, str]
) -> None:
    response = secure_client.get("/checks", headers=headers)

    assert response.status_code == 401
    assert response.content == b'{"detail":"unauthorized"}'
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_credential_failures_are_indistinguishable_from_each_other(
    secure_client: TestClient,
) -> None:
    responses = [secure_client.get("/checks", headers=headers) for headers in CREDENTIAL_FAILURES]

    assert len({response.content for response in responses}) == 1
    assert len({response.status_code for response in responses}) == 1


def test_a_known_demo_token_authenticates(secure_client: TestClient) -> None:
    response = secure_client.get("/checks", headers={"Authorization": f"Bearer {ALPHA_TOKEN}"})

    assert response.status_code == 200
    assert response.json() == []


def test_demo_tokens_are_unmistakably_fake() -> None:
    assert set(DEMO_TOKENS) == {
        "demo-token-alpha-not-a-real-secret",
        "demo-token-bravo-not-a-real-secret",
    }
    assert all(token.startswith("demo-token-") for token in DEMO_TOKENS)
