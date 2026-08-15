"""The Compose file is part of the safety boundary, so it is asserted like everything else."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[1] / "compose.yaml").read_text())
SERVICES: dict[str, Any] = COMPOSE["services"]


def test_the_secure_application_is_the_default_service() -> None:
    secure = SERVICES["secure"]

    # No profile means `docker compose up` starts it.
    assert "profiles" not in secure
    assert "pingjack.apps.secure:app" in " ".join(secure["command"])


def test_the_secure_port_is_published_on_loopback_only() -> None:
    assert SERVICES["secure"]["ports"] == ["127.0.0.1:8000:8000"]


def test_the_vulnerable_service_is_behind_its_own_profile() -> None:
    vulnerable = SERVICES["vulnerable"]

    assert vulnerable["profiles"] == ["vulnerable"]
    assert vulnerable["ports"] == ["127.0.0.1:8001:8001"]
    # The acknowledgement is passed through from the host, and defaults to absent.
    assert vulnerable["environment"]["ALLOW_VULNERABLE_DEMO"] == "${ALLOW_VULNERABLE_DEMO:-}"
    # Built through the factory, so the gate runs before any server exists.
    command = " ".join(vulnerable["command"])
    assert "pingjack.apps.vulnerable:create" in command
    assert "--factory" in command


def test_only_the_secure_service_starts_by_default() -> None:
    default = [name for name, service in SERVICES.items() if "profiles" not in service]

    assert default == ["secure"]


def test_the_verification_service_is_not_started_by_default_and_has_no_network() -> None:
    verify = SERVICES["verify"]

    assert verify["profiles"] == ["verify"]
    assert verify["network_mode"] == "none"


def test_no_service_publishes_a_port_outside_loopback() -> None:
    published = [port for service in SERVICES.values() for port in service.get("ports", [])]

    assert published, "expected at least one published port"
    assert all(port.startswith("127.0.0.1:") for port in published)
