"""The comparison engine, driven directly - no servers, no terminal input."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from pingjack.scenario import (
    ARGUMENT_PAYLOAD,
    FLEET_HOST,
    METACHARACTER_PAYLOAD,
    NAIVE,
    NOTHING_CONSTRUCTED,
    SECURE,
    VULNERABLE,
    constructed_invocation,
    run_scripted_comparison,
)
from tests.conftest import ALPHA_TOKEN


@pytest.fixture
def clients(
    secure_client: TestClient, vulnerable_client: TestClient, naive_client: TestClient
) -> dict[str, httpx.Client]:
    """A TestClient is an httpx.Client, so the engine drives the real applications directly."""
    return {SECURE: secure_client, VULNERABLE: vulnerable_client, NAIVE: naive_client}


def test_the_scripted_run_demonstrates_every_required_outcome(
    clients: dict[str, httpx.Client],
) -> None:
    report = run_scripted_comparison(clients, ALPHA_TOKEN)

    assert report.demonstrates_every_outcome


def test_the_vulnerable_service_discloses_through_metacharacters(
    clients: dict[str, httpx.Client],
) -> None:
    result = run_scripted_comparison(clients, ALPHA_TOKEN).by_application(VULNERABLE)

    assert result.disclosed
    assert [exchange.status_code for exchange in result.exchanges] == [201]
    assert result.verdict.startswith("VULNERABLE")


def test_the_naive_service_resists_one_payload_and_falls_to_the_other(
    clients: dict[str, httpx.Client],
) -> None:
    result = run_scripted_comparison(clients, ALPHA_TOKEN).by_application(NAIVE)

    metacharacter, argument = result.exchanges
    assert metacharacter.submitted == METACHARACTER_PAYLOAD
    assert not metacharacter.disclosed_fixture
    assert argument.submitted == ARGUMENT_PAYLOAD
    assert argument.disclosed_fixture
    assert result.verdict.startswith("STILL VULNERABLE")


def test_the_secure_service_refuses_both_and_still_works(
    clients: dict[str, httpx.Client],
) -> None:
    result = run_scripted_comparison(clients, ALPHA_TOKEN).by_application(SECURE)

    rejections = result.exchanges[:2]
    legitimate = result.exchanges[2]
    assert [exchange.status_code for exchange in rejections] == [400, 400]
    assert len({exchange.body for exchange in rejections}) == 1
    assert not result.disclosed
    assert result.history_unchanged_by_rejections
    assert legitimate.status_code == 201
    assert result.records_after == result.records_before + 1
    assert result.verdict.startswith("SECURE")


def test_the_run_is_deterministic(clients: dict[str, httpx.Client]) -> None:
    first = run_scripted_comparison(clients, ALPHA_TOKEN)
    second = run_scripted_comparison(clients, ALPHA_TOKEN)

    def shape(report: object) -> list[tuple[str, str, int, bool]]:
        assert hasattr(report, "results")
        return [
            (
                exchange.application,
                exchange.submitted,
                exchange.status_code,
                exchange.disclosed_fixture,
            )
            for result in report.results
            for exchange in result.exchanges
        ]

    assert shape(first) == shape(second)


def test_the_rendered_invocation_matches_what_each_service_builds() -> None:
    assert "/bin/sh -c" in constructed_invocation(VULNERABLE, METACHARACTER_PAYLOAD)
    assert METACHARACTER_PAYLOAD in constructed_invocation(VULNERABLE, METACHARACTER_PAYLOAD)

    naive_rendered = constructed_invocation(NAIVE, ARGUMENT_PAYLOAD)
    assert "--config" in naive_rendered
    assert "/bin/sh" not in naive_rendered

    assert constructed_invocation(SECURE, METACHARACTER_PAYLOAD) == NOTHING_CONSTRUCTED
    assert constructed_invocation(SECURE, "relay-9.internal.test") == NOTHING_CONSTRUCTED
    assert FLEET_HOST in constructed_invocation(SECURE, FLEET_HOST)
