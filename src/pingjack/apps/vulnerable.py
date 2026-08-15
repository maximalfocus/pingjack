"""The vulnerable application: interpolate into a string, then hand it to a shell.

**This application is deliberately broken.** It is local educational code and must never be
deployed anywhere.

Compare it with ``pingjack.apps.secure``. Everything else - authentication, storage, the HTTP
contract - is identical. The only difference is these two lines: the submitted value is pasted into
a command string, and that string is given to a shell to interpret. That is enough to turn a
hostname field into arbitrary command execution.

The application is built by a factory rather than exposed as a module-level ``app``, so that
importing this module (to read it, or to test it) never starts an unsafe server.
"""

from __future__ import annotations

from fastapi import FastAPI

from pingjack.execution import PROBE_COUNT, CheckOutcome, probe_executable, run_shell
from pingjack.gating import require_acknowledgement
from pingjack.service import create_app

APPLICATION_NAME = "vulnerable"


def build_command(host: str) -> str:
    """Build the command string, interpolating the submitted value straight into it.

    Nothing here escapes, quotes, or validates ``host``. Whatever the operator typed becomes part
    of the command the shell will parse.
    """
    return f"{probe_executable()} --count {PROBE_COUNT} {host}"


def run_vulnerable_check(host: str) -> CheckOutcome:
    """Run the submitted value as part of a shell command string."""
    return run_shell(build_command(host))


def create() -> FastAPI:
    """Build the vulnerable application, if and only if the operator acknowledged what it is."""
    require_acknowledgement(APPLICATION_NAME)
    return create_app(
        executor=run_vulnerable_check,
        title="pingjack vulnerable check service",
        summary="Intentionally vulnerable. Interpolates the submitted host into a command string "
        "and executes it through a shell.",
    )
