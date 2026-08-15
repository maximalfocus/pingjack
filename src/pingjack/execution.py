"""How a check is executed, and what an execution produced.

The three planned applications share everything here. They differ only in how each one turns a
submitted value into the invocation it hands to the operating system - which is the whole subject
of the demonstration.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Literal

from pingjack.probe import PROBE_COMMAND

#: Fixed number of result lines the applications ask the probe for.
PROBE_COUNT = 1

#: A probe invocation should never be able to block the demonstration forever.
PROBE_TIMEOUT_SECONDS = 10

TIMEOUT_EXIT_STATUS = 124


@cache
def probe_executable() -> str:
    """Return the absolute path of the bundled probe.

    Resolved from a constant name, never from request data or configuration, so no caller can point
    an application at a different executable.
    """
    resolved = shutil.which(PROBE_COMMAND)
    if resolved is None:  # pragma: no cover - the image always installs the console script
        raise RuntimeError(f"the bundled probe {PROBE_COMMAND!r} is not installed")
    return resolved


class RejectionClass(StrEnum):
    """Why a submission was refused. Recorded server side only."""

    HOSTNAME_SYNTAX = "hostname_syntax"
    FLEET_MEMBERSHIP = "fleet_membership"


@dataclass(frozen=True, slots=True)
class Invocation:
    """Exactly what an application handed to the operating system."""

    kind: Literal["argv", "shell"]
    argv: tuple[str, ...] = ()
    command: str = ""

    def rendered(self) -> str:
        """Return a readable rendering of the invocation."""
        if self.kind == "shell":
            return f"/bin/sh -c {shlex.quote(self.command)}"
        return " ".join(shlex.quote(argument) for argument in self.argv)


@dataclass(frozen=True, slots=True)
class CompletedCheck:
    """A check that ran, whatever the submitted value turned out to do."""

    output: str
    exit_status: int
    invocation: Invocation


@dataclass(frozen=True, slots=True)
class RejectedCheck:
    """A submission refused before any process was created."""

    rejection_class: RejectionClass


CheckOutcome = CompletedCheck | RejectedCheck


def run_argv(argv: tuple[str, ...]) -> CompletedCheck:
    """Run ``argv`` directly, with no shell.

    Each element is one argument. Nothing in it is ever parsed for metacharacters, because no shell
    ever sees it.
    """
    invocation = Invocation(kind="argv", argv=argv)
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable, argument vector, no shell
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return CompletedCheck(
            output="probe timed out\n", exit_status=TIMEOUT_EXIT_STATUS, invocation=invocation
        )
    return CompletedCheck(
        output=completed.stdout, exit_status=completed.returncode, invocation=invocation
    )


def run_shell(command: str) -> CompletedCheck:
    """Run ``command`` by asking a shell to interpret the string.

    Deliberately unsafe, and used only by the intentionally vulnerable application. The shell parses
    the entire string, so anything inside it that looks like shell syntax - ``;``, ``&&``, ``|``,
    ``$(...)``, backticks - becomes shell syntax rather than data. This is the flaw the project
    exists to demonstrate; never write this.
    """
    invocation = Invocation(kind="shell", command=command)
    try:
        completed = subprocess.run(  # noqa: S602 - the demonstrated vulnerability, by design
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return CompletedCheck(
            output="probe timed out\n", exit_status=TIMEOUT_EXIT_STATUS, invocation=invocation
        )
    return CompletedCheck(
        output=completed.stdout, exit_status=completed.returncode, invocation=invocation
    )
