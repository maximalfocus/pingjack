"""The two-action opt-in gate for the intentionally unsafe applications."""

from __future__ import annotations

import pytest

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


def test_the_exact_acknowledgement_permits_the_start() -> None:
    require_acknowledgement("vulnerable", {ACKNOWLEDGEMENT_ENV: ACKNOWLEDGEMENT_VALUE})


def test_the_vulnerable_application_refuses_to_build_without_the_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ACKNOWLEDGEMENT_ENV, raising=False)

    with pytest.raises(VulnerableDemoNotAcknowledgedError):
        create_vulnerable()


def test_the_vulnerable_application_builds_with_the_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ACKNOWLEDGEMENT_ENV, ACKNOWLEDGEMENT_VALUE)

    assert create_vulnerable().title == "pingjack vulnerable check service"


def test_importing_the_module_does_not_start_an_unsafe_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ACKNOWLEDGEMENT_ENV, raising=False)

    # Already imported at module scope above without an acknowledgement, and there is no
    # module-level `app` that a runner could pick up by accident.
    import pingjack.apps.vulnerable as module

    assert not hasattr(module, "app")
