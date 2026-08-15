"""The fictional fleet and the fictional operators that check it.

Everything in this module is invented for the demonstration. The hosts live under the reserved
``.test`` domain so that they can never resolve to a real system, and the operators are synthetic
call signs rather than people.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The complete fleet. Membership in this tuple is the allowlist the secure application validates
#: against; the ordering is fixed so that any rendering of the fleet is deterministic.
FLEET_HOSTS: tuple[str, ...] = (
    "relay-7.internal.test",
    "relay-8.internal.test",
    "gateway-1.internal.test",
    "archive-2.internal.test",
)

#: Absolute path of the fictional sensitive fixture baked into the image. It is a constant so that
#: no request or configuration value can point the demonstration at another file.
FLEET_DEPLOY_KEY_PATH = "/srv/netops/fleet_deploy.key"


@dataclass(frozen=True, slots=True)
class Operator:
    """A fictional Meridian Fleet Operations user."""

    id: str
    display_name: str


#: The fictional operator registry. Their credentials are added by the API slice; here they exist
#: only as the owners a check record can belong to.
OPERATORS: tuple[Operator, ...] = (
    Operator(id="operator-alpha", display_name="Meridian Operator Alpha"),
    Operator(id="operator-bravo", display_name="Meridian Operator Bravo"),
)


def is_fleet_host(host: str) -> bool:
    """Return whether ``host`` is exactly one of the fictional fleet members."""
    return host in FLEET_HOSTS


def find_operator(operator_id: str) -> Operator | None:
    """Return the fictional operator with ``operator_id``, or ``None`` when there is no such one."""
    for operator in OPERATORS:
        if operator.id == operator_id:
            return operator
    return None
