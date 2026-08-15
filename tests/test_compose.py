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


def test_the_verification_service_is_not_started_by_default_and_has_no_network() -> None:
    verify = SERVICES["verify"]

    assert verify["profiles"] == ["verify"]
    assert verify["network_mode"] == "none"


def test_no_service_publishes_a_port_outside_loopback() -> None:
    published = [port for service in SERVICES.values() for port in service.get("ports", [])]

    assert published, "expected at least one published port"
    assert all(port.startswith("127.0.0.1:") for port in published)
