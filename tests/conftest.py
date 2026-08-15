"""Shared fixtures.

Each client gets its own application instance, and therefore its own fresh in-memory database.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from pingjack.apps.secure import run_secure_check
from pingjack.apps.vulnerable import create as create_vulnerable
from pingjack.gating import ACKNOWLEDGEMENT_ENV, ACKNOWLEDGEMENT_VALUE
from pingjack.service import create_app

ALPHA_TOKEN = "demo-token-alpha-not-a-real-secret"  # noqa: S105 - fictional demo credential
BRAVO_TOKEN = "demo-token-bravo-not-a-real-secret"  # noqa: S105 - fictional demo credential

FLEET_HOST = "relay-7.internal.test"
METACHARACTER_PAYLOAD = "relay-7.internal.test; cat /srv/netops/fleet_deploy.key"
ARGUMENT_PAYLOAD = "--config /srv/netops/fleet_deploy.key"


def bearer(token: str) -> dict[str, str]:
    """Return the authorization header for ``token``."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def secure_client() -> Iterator[TestClient]:
    app = create_app(
        executor=run_secure_check,
        title="pingjack secure check service",
        summary="test instance",
    )
    with TestClient(app) as client:
        yield client


@pytest.fixture
def vulnerable_client() -> Iterator[TestClient]:
    # Built through the real factory, so the opt-in gate is exercised rather than bypassed.
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(ACKNOWLEDGEMENT_ENV, ACKNOWLEDGEMENT_VALUE)
        with TestClient(create_vulnerable()) as client:
            yield client
