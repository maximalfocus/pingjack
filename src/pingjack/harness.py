"""Start the three applications inside the demo container, then take them away again.

The one-shot demo needs real HTTP over real sockets, not an in-process shortcut - the point is to
show the applications behaving as servers. Everything stays on the container's loopback interface
and every database is a fresh temporary file that disappears with the container.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx

from pingjack.gating import ACKNOWLEDGEMENT_ENV, ACKNOWLEDGEMENT_VALUE
from pingjack.scenario import NAIVE, SECURE, VULNERABLE

HOST = "127.0.0.1"
PORTS = {SECURE: 8000, VULNERABLE: 8001, NAIVE: 8002}
FACTORIES = {
    SECURE: "pingjack.apps.secure:app",
    VULNERABLE: "pingjack.apps.vulnerable:create",
    NAIVE: "pingjack.apps.naive:create",
}

STARTUP_TIMEOUT_SECONDS = 30.0
SHUTDOWN_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class RunningApplication:
    """One application process and how to reach it."""

    name: str
    process: subprocess.Popen[bytes]
    base_url: str


def _uvicorn() -> str:
    resolved = shutil.which("uvicorn")
    if resolved is None:  # pragma: no cover - the image always installs uvicorn
        raise RuntimeError("uvicorn is not installed in this image")
    return resolved


def _start(name: str, database: Path) -> RunningApplication:
    port = PORTS[name]
    target = FACTORIES[name]
    command = [_uvicorn(), target, "--host", HOST, "--port", str(port), "--log-level", "warning"]
    if target.endswith(":create"):
        command.append("--factory")
    environment = {
        **os.environ,
        "PINGJACK_DATABASE_URL": f"sqlite:///{database}",
        ACKNOWLEDGEMENT_ENV: ACKNOWLEDGEMENT_VALUE,
    }
    process = subprocess.Popen(  # noqa: S603 - fixed executable and arguments, no shell
        command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return RunningApplication(name=name, process=process, base_url=f"http://{HOST}:{port}")


def _wait_until_listening(application: RunningApplication) -> None:
    port = PORTS[application.name]
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if application.process.poll() is not None:
            raise RuntimeError(f"the {application.name} application exited before it was ready")
        with contextlib.suppress(OSError), socket.create_connection((HOST, port), timeout=0.5):
            return
        time.sleep(0.05)
    raise TimeoutError(f"the {application.name} application never started listening on {port}")


def _stop(application: RunningApplication) -> None:
    application.process.terminate()
    try:
        application.process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:  # pragma: no cover - only if a process ignores SIGTERM
        application.process.kill()
        application.process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)


@contextlib.contextmanager
def local_applications() -> Iterator[dict[str, httpx.Client]]:
    """Run all three applications against fresh databases, yielding a client for each.

    On the way out every process is stopped and every database file is removed, so a repeated run
    starts from the same empty state.
    """
    with tempfile.TemporaryDirectory(prefix="pingjack-demo-") as directory:
        started: list[RunningApplication] = []
        clients: dict[str, httpx.Client] = {}
        try:
            for name in (SECURE, VULNERABLE, NAIVE):
                application = _start(name, Path(directory) / f"{name}.db")
                started.append(application)
                _wait_until_listening(application)
                clients[name] = httpx.Client(base_url=application.base_url, timeout=30.0)
            yield clients
        finally:
            for client in clients.values():
                client.close()
            for application in started:
                _stop(application)
