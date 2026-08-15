"""No shell, no validation: immune to one payload, wide open to the other."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest
from fastapi.testclient import TestClient

from pingjack.apps.naive import build_argv, run_naive_check
from pingjack.execution import CompletedCheck, probe_executable
from pingjack.fleet import FLEET_DEPLOY_KEY_PATH
from pingjack.probe import BANNER
from tests.conftest import (
    ALPHA_TOKEN,
    ARGUMENT_PAYLOAD,
    FLEET_HOST,
    METACHARACTER_PAYLOAD,
    bearer,
)

FIXTURE_MARKER = "FICTIONAL DEMO FIXTURE"


# --- immune to the metacharacter payload ---


def test_the_metacharacter_payload_becomes_one_literal_argument() -> None:
    argv = build_argv(METACHARACTER_PAYLOAD)

    assert argv == (probe_executable(), "--count", "1", METACHARACTER_PAYLOAD)
    assert len(argv) == 4


def test_the_metacharacter_payload_runs_no_injected_command() -> None:
    outcome = run_naive_check(METACHARACTER_PAYLOAD)

    assert isinstance(outcome, CompletedCheck)
    # The whole payload was reported back as an unreachable host - it was data, not syntax.
    assert FIXTURE_MARKER not in outcome.output
    assert f'no reply from "{METACHARACTER_PAYLOAD}"' in outcome.output
    assert outcome.exit_status == 1


def test_the_metacharacter_payload_discloses_nothing_over_http(naive_client: TestClient) -> None:
    response = naive_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert FIXTURE_MARKER not in response.json()["output"]


# --- and still vulnerable to argument injection ---


def test_the_argument_payload_is_appended_as_probe_options() -> None:
    argv = build_argv(ARGUMENT_PAYLOAD)

    assert argv == (probe_executable(), "--count", "1", "--config", FLEET_DEPLOY_KEY_PATH)


def test_the_argument_payload_discloses_the_fixture() -> None:
    outcome = run_naive_check(ARGUMENT_PAYLOAD)

    assert isinstance(outcome, CompletedCheck)
    assert outcome.invocation.kind == "argv"
    assert FIXTURE_MARKER in outcome.output


def test_the_argument_payload_returns_201_with_the_fixture(naive_client: TestClient) -> None:
    response = naive_client.post(
        "/checks", json={"host": ARGUMENT_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert FIXTURE_MARKER in response.json()["output"]


def test_the_disclosed_fixture_is_stored_in_the_check_record(naive_client: TestClient) -> None:
    naive_client.post("/checks", json={"host": ARGUMENT_PAYLOAD}, headers=bearer(ALPHA_TOKEN))

    records = naive_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()

    assert len(records) == 1
    assert FIXTURE_MARKER in records[0]["output"]
    assert records[0]["host"] == ARGUMENT_PAYLOAD


# --- no shell, anywhere ---


def test_this_application_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, dict[str, Any]]] = []
    real = subprocess.run

    def spy(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - transparent pass-through spy
        seen.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)

    for payload in (METACHARACTER_PAYLOAD, ARGUMENT_PAYLOAD, FLEET_HOST):
        run_naive_check(payload)

    assert len(seen) == 3
    for args, kwargs in seen:
        assert kwargs.get("shell", False) is False
        # A sequence, never a string: the operating system receives argument boundaries directly.
        assert isinstance(args[0], tuple)


def test_a_legitimate_host_still_behaves_normally(naive_client: TestClient) -> None:
    response = naive_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    body = response.json()
    assert response.status_code == 201
    assert body["exit_status"] == 0
    assert BANNER in body["output"]
    assert FIXTURE_MARKER not in body["output"]


def test_the_naive_application_still_requires_authentication(naive_client: TestClient) -> None:
    assert naive_client.post("/checks", json={"host": FLEET_HOST}).status_code == 401
