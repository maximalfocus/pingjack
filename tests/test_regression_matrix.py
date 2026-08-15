"""The security regression matrix.

One module, one property per section, covering all three applications side by side. The per-service
test modules go deeper; this is the matrix that must never go red.
"""

from __future__ import annotations

import json
import shutil
import socket
import statistics
import subprocess
import time
from typing import NoReturn

import pytest
from fastapi.testclient import TestClient

from pingjack.apps import naive, secure, vulnerable
from pingjack.execution import CompletedCheck, RejectedCheck, RejectionClass
from pingjack.probe import BANNER, PROBE_COMMAND
from pingjack.scenario import ARGUMENT_PAYLOAD, FIXTURE_MARKER, METACHARACTER_PAYLOAD
from tests.conftest import ALPHA_TOKEN, FLEET_HOST, bearer

PAYLOADS = [METACHARACTER_PAYLOAD, ARGUMENT_PAYLOAD]


def _forbidden(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("no process may be created here")


# --- 1. the vulnerable metacharacter injection runs and discloses the fixture ---


def test_vulnerable_metacharacter_injection_returns_the_fixture(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    output = response.json()["output"]
    assert BANNER in output
    assert FIXTURE_MARKER in output


# --- 2. the vulnerable command string carries the submitted metacharacters ---


def test_vulnerable_command_string_carries_the_metacharacters() -> None:
    command = vulnerable.build_command(METACHARACTER_PAYLOAD)

    assert "; cat " in command
    assert command.endswith(METACHARACTER_PAYLOAD)


# --- 3. the naive application is immune to the metacharacter payload ---


def test_naive_treats_the_metacharacter_payload_as_one_literal_argument(
    naive_client: TestClient,
) -> None:
    argv = naive.build_argv(METACHARACTER_PAYLOAD)
    assert argv[-1] == METACHARACTER_PAYLOAD
    assert len(argv) == 4

    response = naive_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert FIXTURE_MARKER not in response.json()["output"]


# --- 4. the naive application still falls to argument injection ---


def test_naive_argument_injection_returns_the_same_fixture(naive_client: TestClient) -> None:
    response = naive_client.post(
        "/checks", json={"host": ARGUMENT_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )

    assert response.status_code == 201
    assert FIXTURE_MARKER in response.json()["output"]


# --- 5. the secure application refuses both, identically, with no trace ---


def test_secure_rejects_both_payloads_identically_and_changes_nothing(
    secure_client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))
    before = secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content
    capsys.readouterr()

    responses = [
        secure_client.post("/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN))
        for payload in PAYLOADS
    ]
    events = [
        json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")
    ]

    assert [response.status_code for response in responses] == [400, 400]
    assert len({response.content for response in responses}) == 1
    assert secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).content == before
    assert len(events) == 2
    assert all(event["event"] == "check.rejected" for event in events)
    assert all(FIXTURE_MARKER not in json.dumps(event) for event in events)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_secure_rejection_starts_no_process(
    secure_client: TestClient, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    monkeypatch.setattr(subprocess, "run", _forbidden)

    assert (
        secure_client.post(
            "/checks", json={"host": payload}, headers=bearer(ALPHA_TOKEN)
        ).status_code
        == 400
    )


# --- 6. neither the response nor the timing reveals which check refused ---


def test_secure_rejection_response_reveals_no_class(secure_client: TestClient) -> None:
    syntax = secure_client.post(
        "/checks", json={"host": METACHARACTER_PAYLOAD}, headers=bearer(ALPHA_TOKEN)
    )
    membership = secure_client.post(
        "/checks", json={"host": "relay-9.internal.test"}, headers=bearer(ALPHA_TOKEN)
    )

    assert syntax.content == membership.content
    assert syntax.status_code == membership.status_code
    assert syntax.headers["content-length"] == membership.headers["content-length"]


def test_secure_rejection_timing_reveals_no_class() -> None:
    # Both classes are refused by cheap string work before any process exists, so the medians sit
    # microseconds apart. The bound is deliberately loose: this must never be flaky.
    assert isinstance(secure.run_secure_check(METACHARACTER_PAYLOAD), RejectedCheck)
    assert isinstance(secure.run_secure_check("relay-9.internal.test"), RejectedCheck)

    def median_seconds(host: str) -> float:
        samples = []
        for _ in range(200):
            started = time.perf_counter()
            secure.run_secure_check(host)
            samples.append(time.perf_counter() - started)
        return statistics.median(samples)

    syntax = median_seconds(METACHARACTER_PAYLOAD)
    membership = median_seconds("relay-9.internal.test")

    assert abs(syntax - membership) < 0.002
    assert 0.1 < (syntax / membership) < 10


# --- 7. a legitimate check returns the expected output and appends exactly one record ---


def test_legitimate_check_returns_deterministic_output_and_one_record(
    secure_client: TestClient,
) -> None:
    expected = f"{BANNER}\nreply from {FLEET_HOST}: seq=1 bytes=64 status=ok\n"

    first = secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))
    second = secure_client.post("/checks", json={"host": FLEET_HOST}, headers=bearer(ALPHA_TOKEN))

    assert first.status_code == second.status_code == 201
    assert first.json()["output"] == second.json()["output"] == expected
    assert len(secure_client.get("/checks", headers=bearer(ALPHA_TOKEN)).json()) == 2


# --- 8. every credential failure looks the same, on every application ---


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic YWJjOmRlZg=="},
        {"Authorization": "Bearer nope-not-a-known-token"},
    ],
)
def test_generic_401_on_every_application(
    secure_client: TestClient,
    vulnerable_client: TestClient,
    naive_client: TestClient,
    headers: dict[str, str],
) -> None:
    responses = [
        client.post("/checks", json={"host": FLEET_HOST}, headers=headers)
        for client in (secure_client, vulnerable_client, naive_client)
    ]

    assert {response.status_code for response in responses} == {401}
    assert {response.content for response in responses} == {b'{"detail":"unauthorized"}'}
    assert all(response.headers["WWW-Authenticate"] == "Bearer" for response in responses)


# --- 9. the probe is byte-deterministic and never touches the network ---


def test_probe_is_byte_deterministic_across_invocations() -> None:
    executable = shutil.which(PROBE_COMMAND)
    assert executable is not None

    runs = [
        subprocess.run(  # noqa: S603 - fixed executable, no external input
            [executable, "--count", "3", FLEET_HOST], capture_output=True, check=False
        )
        for _ in range(3)
    ]

    assert len({run.stdout for run in runs}) == 1
    assert {run.returncode for run in runs} == {0}


def test_probe_performs_no_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden)

    outcome = secure.run_secure_check(FLEET_HOST)

    assert isinstance(outcome, CompletedCheck)
    assert BANNER in outcome.output


def test_the_two_rejection_classes_exist_and_stay_server_side() -> None:
    assert {member.value for member in RejectionClass} == {
        "hostname_syntax",
        "fleet_membership",
    }
