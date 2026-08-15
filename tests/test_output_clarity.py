"""Default output must stand on its own, without reading any source code."""

from __future__ import annotations

import io

import httpx
import pytest
from fastapi.testclient import TestClient

from pingjack.cli import render
from pingjack.scenario import (
    ARGUMENT_PAYLOAD,
    METACHARACTER_PAYLOAD,
    NAIVE,
    SECURE,
    VULNERABLE,
    run_scripted_comparison,
    summarise_probe_output,
)
from tests.conftest import ALPHA_TOKEN


@pytest.fixture
def rendered(
    secure_client: TestClient, vulnerable_client: TestClient, naive_client: TestClient
) -> str:
    clients: dict[str, httpx.Client] = {
        SECURE: secure_client,
        VULNERABLE: vulnerable_client,
        NAIVE: naive_client,
    }
    report = run_scripted_comparison(clients, ALPHA_TOKEN)
    stream = io.StringIO()
    render(report, stream, verbose=False)
    return stream.getvalue()


def test_default_output_shows_the_submitted_value(rendered: str) -> None:
    assert f"submitted         : {METACHARACTER_PAYLOAD}" in rendered
    assert f"submitted         : {ARGUMENT_PAYLOAD}" in rendered


def test_default_output_shows_what_the_server_constructed(rendered: str) -> None:
    assert "server constructed: /bin/sh -c " in rendered
    assert "server constructed: /usr/local/bin/fleetprobe --count 1 --config" in rendered
    assert "server constructed: (nothing - refused before any process was created)" in rendered


def test_default_output_shows_the_response_status(rendered: str) -> None:
    assert "response          : HTTP 201" in rendered
    assert "response          : HTTP 400" in rendered


def test_default_output_says_what_the_probe_output_contained(rendered: str) -> None:
    assert "probe output      : the link check reply, and the contents of the fictional key" in (
        rendered
    )
    assert "probe output      : the contents of the fictional key fixture" in rendered
    assert "probe output      : an unreachable report only" in rendered
    assert "probe output      : the link check reply only" in rendered
    assert "probe output      : (none - no process ran)" in rendered


def test_default_output_says_whether_a_record_was_created(rendered: str) -> None:
    assert "check record      : created" in rendered
    assert "check record      : none created" in rendered


def test_default_output_ends_with_a_verdict_per_service(rendered: str) -> None:
    assert rendered.count("VERDICT:") == 3
    assert "VULNERABLE - a shell parsed the submitted value" in rendered
    assert "STILL VULNERABLE - no shell was involved" in rendered
    assert "SECURE - both payloads refused before any process existed" in rendered


def test_default_output_needs_no_source_reading_for_the_history_claim(rendered: str) -> None:
    assert "check history before:" in rendered
    assert "check history after :" in rendered
    assert "history byte-for-byte unchanged by the rejections: yes" in rendered


@pytest.mark.parametrize(
    ("output", "disclosed", "expected"),
    [
        ("", False, "(none - no process ran)"),
        ("banner\nreply from x\n", False, "the link check reply only"),
        ("banner\nno reply from x\n", False, "an unreachable report only"),
        ("banner\nreply from x\nFIXTURE\n", True, "the link check reply, and the contents"),
        ("banner\nconfig[x]: FIXTURE\n", True, "the contents of the fictional key fixture"),
    ],
)
def test_the_probe_summary_describes_each_shape(
    output: str, disclosed: bool, expected: str
) -> None:
    assert summarise_probe_output(output, disclosed=disclosed).startswith(expected)
