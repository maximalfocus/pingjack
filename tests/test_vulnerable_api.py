"""What the shell-string application does with a submitted value."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pingjack.apps.vulnerable import build_command, run_vulnerable_check
from pingjack.execution import CompletedCheck, probe_executable
from pingjack.fleet import FLEET_DEPLOY_KEY_PATH
from pingjack.probe import BANNER
from tests.conftest import ALPHA_TOKEN, FLEET_HOST, METACHARACTER_PAYLOAD, bearer

FIXTURE_MARKER = "FICTIONAL DEMO FIXTURE"


def test_the_command_string_carries_the_submitted_metacharacters() -> None:
    command = build_command(METACHARACTER_PAYLOAD)

    assert command.endswith(f"; cat {FLEET_DEPLOY_KEY_PATH}")
    assert ";" in command
    assert command.startswith(probe_executable())


def test_the_injected_command_runs_and_discloses_the_fixture() -> None:
    outcome = run_vulnerable_check(METACHARACTER_PAYLOAD)

    assert isinstance(outcome, CompletedCheck)
    assert outcome.invocation.kind == "shell"
    # Both halves are present: the probe did its job, and so did the injected command.
    assert BANNER in outcome.output
    assert f"reply from {FLEET_HOST}" in outcome.output
    assert FIXTURE_MARKER in outcome.output


def test_the_injection_looks_like_an_ordinary_success(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    body = response.json()
    assert body["exit_status"] == 0
    assert FIXTURE_MARKER in body["output"]


def test_the_disclosed_fixture_is_stored_in_the_check_record(
    vulnerable_client: TestClient,
) -> None:
    vulnerable_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    records = vulnerable_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()

    assert len(records) == 1
    assert FIXTURE_MARKER in records[0]["output"]
    assert records[0]["host"] == METACHARACTER_PAYLOAD


def test_a_legitimate_host_still_behaves_normally(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.post(
        "/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert FIXTURE_MARKER not in response.json()["output"]


def test_the_vulnerable_application_still_requires_authentication(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.post("/checks", json={"host": FLEET_HOST})

    assert response.status_code == 401


@pytest.mark.parametrize(
    "variable", ["PINGJACK_PROBE", "PINGJACK_PROBE_COMMAND", "FLEETPROBE", "PROBE_COMMAND"]
)
def test_no_environment_variable_can_repoint_the_probe(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    monkeypatch.setenv(variable, "/bin/echo")

    assert probe_executable().endswith("fleetprobe")
    assert build_command(FLEET_HOST).startswith(probe_executable())


def test_request_data_cannot_choose_the_executable(vulnerable_client: TestClient) -> None:
    # Even in the vulnerable application, the *executable* is a constant; the injection happens in
    # the arguments the shell parses, not by naming a different program to run.
    response = vulnerable_client.post(
        "/checks", json={"host": FLEET_HOST, "probe": "/bin/echo"}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert BANNER in response.json()["output"]
