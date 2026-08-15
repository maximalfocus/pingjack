"""The secure application: validate first, then run an argument vector.

Two controls, in this order:

1. the submitted value must satisfy a strict hostname syntax rule, and must be a member of the
   fleet allowlist - both checked before any process exists; and
2. the probe is invoked as an argument vector, so no shell ever parses the value.

The first control is the load-bearing one. The second means a shell is never involved at all.
"""

from __future__ import annotations

from pingjack.execution import (
    PROBE_COUNT,
    CheckOutcome,
    RejectedCheck,
    RejectionClass,
    probe_executable,
    run_argv,
)
from pingjack.fleet import is_fleet_host
from pingjack.hostname import is_valid_hostname
from pingjack.service import create_app


def run_secure_check(host: str) -> CheckOutcome:
    """Validate ``host``, then check it - or refuse before creating any process."""
    if not is_valid_hostname(host):
        return RejectedCheck(rejection_class=RejectionClass.HOSTNAME_SYNTAX)
    if not is_fleet_host(host):
        return RejectedCheck(rejection_class=RejectionClass.FLEET_MEMBERSHIP)
    # A fixed argument count, no --config, and the host as a single positional argument.
    return run_argv((probe_executable(), "--count", str(PROBE_COUNT), host))


app = create_app(
    executor=run_secure_check,
    title="pingjack secure check service",
    summary="Validates the submitted host against a strict rule and the fleet allowlist, then runs "
    "the probe as an argument vector.",
)
