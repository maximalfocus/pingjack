"""The fictional fleet and operator registry."""

from __future__ import annotations

from pathlib import Path

from pingjack.fleet import (
    FLEET_DEPLOY_KEY_PATH,
    FLEET_HOSTS,
    OPERATORS,
    find_operator,
    is_fleet_host,
)


def test_fleet_is_four_reserved_test_domain_hosts() -> None:
    assert FLEET_HOSTS == (
        "relay-7.internal.test",
        "relay-8.internal.test",
        "gateway-1.internal.test",
        "archive-2.internal.test",
    )
    assert all(host.endswith(".test") for host in FLEET_HOSTS)


def test_membership_is_exact() -> None:
    assert is_fleet_host("relay-7.internal.test")
    assert not is_fleet_host("relay-7.internal.test.evil.test")
    assert not is_fleet_host("RELAY-7.INTERNAL.TEST")
    assert not is_fleet_host("")


def test_operators_are_synthetic_call_signs() -> None:
    assert {operator.id for operator in OPERATORS} == {"operator-alpha", "operator-bravo"}
    assert find_operator("operator-alpha") is not None
    assert find_operator("operator-nobody") is None


def test_key_fixture_declares_itself_fictional_in_its_own_contents() -> None:
    contents = Path(FLEET_DEPLOY_KEY_PATH).read_text(encoding="utf-8")

    assert "FICTIONAL DEMO FIXTURE" in contents
    assert "NOT A REAL KEY" in contents
    assert "no credential" in contents
    assert "PRIVATE KEY" not in contents
