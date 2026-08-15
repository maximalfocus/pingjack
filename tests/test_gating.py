"""The two-action opt-in gate for the intentionally unsafe applications."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI

from pingjack.apps.naive import create as create_naive
from pingjack.apps.vulnerable import create as create_vulnerable
from pingjack.gating import (
    ACKNOWLEDGEMENT_ENV,
    ACKNOWLEDGEMENT_VALUE,
    COMPOSE_PROFILE,
    VulnerableDemoNotAcknowledgedError,
    require_acknowledgement,
)


@pytest.mark.parametrize(
    "supplied",
    [
        {},
        {ACKNOWLEDGEMENT_ENV: ""},
        {ACKNOWLEDGEMENT_ENV: "yes"},
        {ACKNOWLEDGEMENT_ENV: "TRUE"},
        {ACKNOWLEDGEMENT_ENV: "1"},
        {ACKNOWLEDGEMENT_ENV: "true "},
    ],
)
def test_an_unacknowledged_start_is_refused(supplied: dict[str, str]) -> None:
    with pytest.raises(VulnerableDemoNotAcknowledgedError):
        require_acknowledgement("vulnerable", supplied)


def test_the_refusal_explains_both_required_actions() -> None:
    with pytest.raises(VulnerableDemoNotAcknowledgedError) as raised:
        require_acknowledgement("vulnerable", {})

    message = str(raised.value)
    assert "intentionally vulnerable" in message
    assert COMPOSE_PROFILE in message
    assert f"{ACKNOWLEDGEMENT_ENV}={ACKNOWLEDGEMENT_VALUE}" in message
    assert "two deliberate actions" in message


@pytest.mark.parametrize(
    ("application", "expected"),
    [
        ("vulnerable", "docker compose --profile vulnerable up"),
        ("naive", "docker compose --profile vulnerable up"),
        ("demo", "docker compose --profile demo run --rm demo"),
    ],
)
def test_the_refusal_names_the_command_that_actually_starts_it(
    application: str, expected: str
) -> None:
    with pytest.raises(VulnerableDemoNotAcknowledgedError) as raised:
        require_acknowledgement(application, {})

    assert expected in str(raised.value)


def test_the_exact_acknowledgement_permits_the_start() -> None:
    require_acknowledgement("vulnerable", {ACKNOWLEDGEMENT_ENV: ACKNOWLEDGEMENT_VALUE})


@pytest.mark.parametrize("factory", [create_vulnerable, create_naive])
def test_an_unsafe_application_refuses_to_build_without_the_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, factory: Callable[[], FastAPI]
) -> None:
    monkeypatch.delenv(ACKNOWLEDGEMENT_ENV, raising=False)

    with pytest.raises(VulnerableDemoNotAcknowledgedError):
        factory()


@pytest.mark.parametrize(
    ("factory", "title"),
    [
        (create_vulnerable, "pingjack vulnerable check service"),
        (create_naive, "pingjack naive check service"),
    ],
)
def test_an_unsafe_application_builds_with_the_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, factory: Callable[[], FastAPI], title: str
) -> None:
    monkeypatch.setenv(ACKNOWLEDGEMENT_ENV, ACKNOWLEDGEMENT_VALUE)

    assert factory().title == title


def test_importing_an_unsafe_module_does_not_start_an_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ACKNOWLEDGEMENT_ENV, raising=False)

    # Both were imported at module scope above without an acknowledgement, and neither exposes a
    # module-level `app` that a runner could pick up by accident.
    import pingjack.apps.naive as naive_module
    import pingjack.apps.vulnerable as vulnerable_module

    assert not hasattr(vulnerable_module, "app")
    assert not hasattr(naive_module, "app")
