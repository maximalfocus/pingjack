"""The probe's output contract, determinism, and hermeticity."""

from __future__ import annotations

import os
import random
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import NoReturn

import pytest

from pingjack.fleet import FLEET_HOSTS
from pingjack.probe import BANNER, PROBE_COMMAND, build_report, main

FLEET_HOST = FLEET_HOSTS[0]


def _forbidden(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("the probe must not use this facility")


def test_fleet_host_emits_banner_and_result_lines() -> None:
    lines, status = build_report(FLEET_HOST, 3, None)

    assert lines[0] == BANNER
    assert lines[1:] == [
        f"reply from {FLEET_HOST}: seq={seq} bytes=64 status=ok" for seq in (1, 2, 3)
    ]
    assert status == 0


def test_unknown_host_emits_one_unreachable_line() -> None:
    lines, status = build_report("not-a-fleet-host.test", 3, None)

    assert lines == [BANNER, 'no reply from "not-a-fleet-host.test": link check failed']
    assert status == 1


def test_missing_host_is_reported_rather_than_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    status = main(["--count", "1"])

    assert status == 1
    assert capsys.readouterr().out == f'{BANNER}\nno reply from "": link check failed\n'


def test_config_echoes_the_named_file_on_one_line(tmp_path: Path) -> None:
    profile = tmp_path / "profile.conf"
    profile.write_text("alpha\nbravo\n", encoding="utf-8")

    lines, status = build_report(FLEET_HOST, 1, str(profile))

    assert lines[1] == f"config[{profile}]: alpha bravo"
    assert status == 0


def test_unreadable_config_is_reported_deterministically(tmp_path: Path) -> None:
    missing = tmp_path / "absent.conf"

    lines, _ = build_report(FLEET_HOST, 1, str(missing))

    assert lines[1] == f"config[{missing}]: (unreadable)"


def test_identical_arguments_produce_identical_bytes(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["--count", "4", FLEET_HOST]

    first_status = main(argv)
    first = capsys.readouterr().out
    second_status = main(argv)
    second = capsys.readouterr().out

    assert first.encode() == second.encode()
    assert first_status == second_status == 0


def test_probe_performs_no_network_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden)

    assert main(["--count", "2", FLEET_HOST]) == 0
    assert capsys.readouterr().out.count("reply from") == 2


def test_probe_reads_no_clock_and_uses_no_randomness(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for module, name in (
        (time, "time"),
        (time, "monotonic"),
        (time, "time_ns"),
        (random, "random"),
        (random, "randint"),
        (random, "choice"),
        (os, "urandom"),
        (uuid, "uuid4"),
    ):
        monkeypatch.setattr(module, name, _forbidden)

    assert main(["--count", "1", FLEET_HOST]) == 0
    assert BANNER in capsys.readouterr().out


def test_bundled_console_script_is_installed_and_deterministic() -> None:
    executable = shutil.which(PROBE_COMMAND)
    assert executable is not None, f"{PROBE_COMMAND} must be installed in the image"

    first = subprocess.run(  # noqa: S603 - fixed executable, no external input
        [executable, "--count", "2", FLEET_HOST], capture_output=True, check=False
    )
    second = subprocess.run(  # noqa: S603 - fixed executable, no external input
        [executable, "--count", "2", FLEET_HOST], capture_output=True, check=False
    )

    assert first.returncode == 0
    assert first.stdout == second.stdout
    assert first.stdout.decode().startswith(BANNER)


def test_bundled_console_script_exits_one_for_an_unknown_host() -> None:
    executable = shutil.which(PROBE_COMMAND)
    assert executable is not None

    result = subprocess.run(  # noqa: S603 - fixed executable, no external input
        [executable, "--count", "1", "elsewhere.test"], capture_output=True, check=False
    )

    assert result.returncode == 1
    assert b"link check failed" in result.stdout
