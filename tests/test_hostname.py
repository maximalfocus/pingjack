"""The strict hostname syntax rule."""

from __future__ import annotations

import pytest

from pingjack.fleet import FLEET_HOSTS
from pingjack.hostname import MAX_HOSTNAME_LENGTH, is_valid_hostname


@pytest.mark.parametrize("host", FLEET_HOSTS)
def test_every_fleet_host_satisfies_the_rule(host: str) -> None:
    assert is_valid_hostname(host)


@pytest.mark.parametrize(
    "value",
    [
        "relay-7.internal.test; cat /srv/netops/fleet_deploy.key",
        "--config /srv/netops/fleet_deploy.key",
        "relay-7.internal.test && id",
        "relay-7.internal.test | id",
        "relay-7.internal.test$(id)",
        "relay-7.internal.test`id`",
        "relay-7.internal.test\nid",
        "relay-7.internal.test ",
        "-relay-7.internal.test",
        "relay-7.internal.test-",
        "relay..test",
        "relay-7.internal.test.",
        "RELAY-7.INTERNAL.TEST",
        "relay_7.internal.test",
        "",
        "a" * (MAX_HOSTNAME_LENGTH + 1),
        "a" * 64 + ".test",
    ],
)
def test_the_rule_rejects_anything_it_was_not_written_to_accept(value: str) -> None:
    assert not is_valid_hostname(value)


def test_the_rule_accepts_ordinary_hostnames_outside_the_fleet() -> None:
    # Syntax and membership are separate controls: this one is well formed but not a fleet member.
    assert is_valid_hostname("relay-9.internal.test")
