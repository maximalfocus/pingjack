"""The naive application: no shell, no validation.

**This application is deliberately broken.** It is local educational code and must never be
deployed anywhere.

This is the half fix. Someone read about command injection, removed the shell, and stopped there.
The probe is invoked as an argument vector, so the metacharacter payload that defeats
``pingjack.apps.vulnerable`` is inert here - the ``;`` is just a character inside one literal
argument, and nothing parses it.

But the submitted value is still *appended to the probe's arguments*, and a value that looks like an
option is passed through as one. So an operator can hand the probe a ``--config`` it will honour,
and read a file back through an ordinary ``201`` - with no shell involved anywhere. Removing the
shell was necessary. It was not sufficient. Only validating the input closes this.
"""

from __future__ import annotations

import shlex

from fastapi import FastAPI

from pingjack.execution import PROBE_COUNT, CheckOutcome, probe_executable, run_argv
from pingjack.gating import require_acknowledgement
from pingjack.service import create_app

APPLICATION_NAME = "naive"


def build_argv(host: str) -> tuple[str, ...]:
    """Append the submitted value to the probe's arguments.

    The plausible-looking convenience: a value that starts with a dash is treated as extra probe
    options, so operators can "pass flags through". Anything else is one literal argument. No shell
    is involved either way - and that is precisely why this looks safe and is not.
    """
    if host.startswith("-"):
        try:
            submitted = shlex.split(host)
        except ValueError:
            submitted = [host]
    else:
        submitted = [host]
    return (probe_executable(), "--count", str(PROBE_COUNT), *submitted)


def run_naive_check(host: str) -> CheckOutcome:
    """Run the probe as an argument vector, with the submitted value appended unvalidated."""
    return run_argv(build_argv(host))


def create() -> FastAPI:
    """Build the naive application, if and only if the operator acknowledged what it is."""
    require_acknowledgement(APPLICATION_NAME)
    return create_app(
        executor=run_naive_check,
        title="pingjack naive check service",
        summary="Intentionally vulnerable. Uses no shell, but appends the unvalidated submitted "
        "value to the probe's arguments.",
    )
