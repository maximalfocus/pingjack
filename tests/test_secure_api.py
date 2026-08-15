"""The secure application's behaviour at the HTTP boundary."""

from __future__ import annotations

import json
import subprocess
from typing import NoReturn

import pytest
from fastapi.testclient import TestClient

from pingjack.apps.secure import run_secure_check
from pingjack.execution import CompletedCheck, RejectedCheck, RejectionClass
from pingjack.fleet import FLEET_DEPLOY_KEY_PATH
from pingjack.probe import BANNER
from tests.conftest import (
    ALPHA_TOKEN,
    ARGUMENT_PAYLOAD,
    BRAVO_TOKEN,
    FLEET_HOST,
    METACHARACTER_PAYLOAD,
    bearer,
)

EXPECTED_OUTPUT = f"{BANNER}\nreply from {FLEET_HOST}: seq=1 bytes=64 status=ok\n"

PAYLOADS = [METACHARACTER_PAYLOAD, ARGUMENT_PAYLOAD]


def _no_process(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("a rejected submission must never create a process")


# --- the legitimate lifecycle ---


def test_a_fleet_host_returns_201_with_deterministic_output(secure_client: TestClient) -> None:
    response = secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    assert response.status_code == 201
    body = response.json()
    assert body["host"] == FLEET_HOST
    assert body["output"] == EXPECTED_OUTPUT
    assert body["exit_status"] == 0


def test_a_successful_check_appends_exactly_one_record(secure_client: TestClient) -> None:
    before = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()

    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    after = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()
    assert len(after) == len(before) + 1


def test_submitting_the_same_host_again_appends_an_independent_record(
    secure_client: TestClient,
) -> None:
    first = secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))
    second = secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    assert first.json()["id"] != second.json()["id"]
    assert len(secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()) == 2


def test_history_returns_only_the_calling_operators_records(secure_client: TestClient) -> None:
    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    bravo = secure_client.get("/checks", headers=bearer(BRAVO_TOKEN))

    assert bravo.json() == []
    assert len(secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()) == 1


def test_history_exposes_host_output_and_exit_status(secure_client: TestClient) -> None:
    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    record = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()[0]

    assert set(record) == {"id", "host", "output", "exit_status"}
    assert record["output"] == EXPECTED_OUTPUT


# --- rejection ---


@pytest.mark.parametrize("payload", PAYLOADS)
def test_both_demonstration_payloads_are_rejected(secure_client: TestClient, payload: str) -> None:
    response = secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))

    assert response.status_code == 400
    assert response.content == b'{"detail":"check request rejected"}'


def test_the_two_rejection_classes_are_indistinguishable_to_the_client(
    secure_client: TestClient,
) -> None:
    # A syntax rejection and a fleet-membership rejection, side by side.
    syntax = secure_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )
    membership = secure_client.post(
        "/checks", json={"host": "relay-9.internal.test"}, headers=bearer(ALPHA_TOKEN)
    )

    assert syntax.status_code == membership.status_code == 400
    assert syntax.content == membership.content
    assert syntax.headers["content-type"] == membership.headers["content-type"]
    assert syntax.headers["content-length"] == membership.headers["content-length"]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_rejected_submission_starts_no_process(
    secure_client: TestClient, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    monkeypatch.setattr(subprocess, "run", _no_process)

    response = secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))

    assert response.status_code == 400


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_rejected_submission_creates_no_record(secure_client: TestClient, payload: str) -> None:
    before = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content

    secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))

    assert secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content == before


def test_check_history_is_byte_for_byte_unchanged_by_a_rejection(
    secure_client: TestClient,
) -> None:
    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))
    before = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content

    for payload in PAYLOADS:
        secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))

    assert secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content == before


# --- the rejection audit event ---


def _rejection_event(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert len(lines) == 1, f"expected exactly one event, got {lines}"
    event: dict[str, object] = json.loads(lines[0])
    return event


def test_a_rejection_emits_one_structured_event(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    response = secure_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    event = _rejection_event(capsys)
    assert event["event"] == "check.rejected"
    assert event["operator_id"] == "operator-alpha"
    assert event["action"] == "check.submit"
    assert event["outcome"] == "rejected"
    assert event["rejection_class"] == RejectionClass.HOSTNAME_SYNTAX.value
    # The correlation identifier is also returned to the client, so a report can be traced.
    assert event["request_id"] == response.headers["X-Request-ID"]


def test_the_event_distinguishes_the_two_rejection_classes(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    secure_client.post(
        "/checks", json={"host": "relay-9.internal.test"}, headers=bearer(ALPHA_TOKEN)
    )

    assert _rejection_event(capsys)["rejection_class"] == RejectionClass.FLEET_MEMBERSHIP.value


def test_the_event_never_carries_tokens_headers_or_fixture_contents(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    secure_client.post("/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN))

    rendered = json.dumps(_rejection_event(capsys))
    assert ALPHA_TOKEN not in rendered
    assert "authorization" not in rendered.lower()
    assert "FICTIONAL DEMO FIXTURE" not in rendered
    assert BANNER not in rendered


def test_the_submitted_value_is_capped_and_escaped(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = "relay-7.internal.test\n\t; cat " + FLEET_DEPLOY_KEY_PATH + "x" * 300

    secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))

    event = _rejection_event(capsys)
    rendered = event["submitted_value"]
    assert isinstance(rendered, str)
    assert len(rendered) <= 200
    assert "\n" not in rendered and "\t" not in rendered
    assert "\\n" in rendered and "\\t" in rendered
    assert event["submitted_value_truncated"] is True
    assert event["submitted_value_length"] == len(payload)


def test_a_successful_check_emits_no_rejection_event(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    assert "check.rejected" not in capsys.readouterr().out


# --- what the application actually constructs ---


def test_the_secure_invocation_is_a_fixed_argument_vector() -> None:
    outcome = run_secure_check(FLEET_HOST)

    assert isinstance(outcome, CompletedCheck)
    assert outcome.invocation.kind == "argv"
    argv = outcome.invocation.argv
    assert len(argv) == 4
    assert argv[0].endswith("fleetprobe")
    assert argv[1:] == ("--count", "1", FLEET_HOST)
    assert "--config" not in argv


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (METACHARACTER_PAYLOAD, RejectionClass.HOSTNAME_SYNTAX),
        (ARGUMENT_PAYLOAD, RejectionClass.HOSTNAME_SYNTAX),
        ("relay-9.internal.test", RejectionClass.FLEET_MEMBERSHIP),
    ],
)
def test_validation_happens_before_any_invocation_is_built(
    payload: str, expected: RejectionClass
) -> None:
    outcome = run_secure_check(payload)

    assert isinstance(outcome, RejectedCheck)
    assert outcome.rejection_class is expected
