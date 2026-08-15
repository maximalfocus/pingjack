"""The opt-in gate for the intentionally unsafe applications.

Starting one of them takes two deliberate actions that are hard to perform by accident: enabling the
``vulnerable`` Compose profile, and setting the acknowledgement variable below. The profile keeps
them out of the default Compose path; the acknowledgement makes sure that whoever started one meant
to.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

ACKNOWLEDGEMENT_ENV = "ALLOW_VULNERABLE_DEMO"
ACKNOWLEDGEMENT_VALUE = "true"
COMPOSE_PROFILE = "vulnerable"


class VulnerableDemoNotAcknowledgedError(RuntimeError):
    """Raised instead of starting an intentionally unsafe application."""


def require_acknowledgement(application: str, environ: Mapping[str, str] | None = None) -> None:
    """Refuse to build an unsafe application unless the acknowledgement is present.

    The message explains both required actions, because the missing one is usually the profile.
    """
    values = os.environ if environ is None else environ
    supplied = values.get(ACKNOWLEDGEMENT_ENV, "")
    if supplied == ACKNOWLEDGEMENT_VALUE:
        return
    raise VulnerableDemoNotAcknowledgedError(
        f"Refusing to start the {application!r} application: it is intentionally vulnerable and is "
        f"local educational code only.\n"
        f"{ACKNOWLEDGEMENT_ENV} is {supplied!r}, but must be {ACKNOWLEDGEMENT_VALUE!r}.\n"
        f"Starting it takes two deliberate actions:\n"
        f"  1. enable the {COMPOSE_PROFILE!r} Compose profile, and\n"
        f"  2. set {ACKNOWLEDGEMENT_ENV}={ACKNOWLEDGEMENT_VALUE}.\n"
        f"For example: {ACKNOWLEDGEMENT_ENV}={ACKNOWLEDGEMENT_VALUE} "
        f"docker compose --profile {COMPOSE_PROFILE} up"
    )
