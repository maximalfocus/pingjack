"""The CLI's argument handling and rendering. No terminal input is simulated."""

from __future__ import annotations

import io

from pingjack.cli import RULE, build_parser, render
from pingjack.scenario import (
    NAIVE,
    SECURE,
    VULNERABLE,
    ApplicationResult,
    Exchange,
    Report,
)


def _exchange(application: str, *, disclosed: bool, status: int = 201) -> Exchange:
    return Exchange(
        application=application,
        submitted="relay-7.internal.test",
        status_code=status,
        body='{"detail":"x"}',
        constructed="fleetprobe --count 1 relay-7.internal.test",
        output="fleetprobe 1.0\nreply\n",
        disclosed_fixture=disclosed,
    )


def _report() -> Report:
    return Report(
        results=(
            ApplicationResult(
                application=VULNERABLE,
                exchanges=(_exchange(VULNERABLE, disclosed=True),),
                records_before=0,
                records_after=1,
                history_unchanged_by_rejections=False,
            ),
            ApplicationResult(
                application=NAIVE,
                exchanges=(
                    _exchange(NAIVE, disclosed=False),
                    _exchange(NAIVE, disclosed=True),
                ),
                records_before=0,
                records_after=2,
                history_unchanged_by_rejections=False,
            ),
            ApplicationResult(
                application=SECURE,
                exchanges=(
                    _exchange(SECURE, disclosed=False, status=400),
                    _exchange(SECURE, disclosed=False, status=400),
                    _exchange(SECURE, disclosed=False),
                ),
                records_before=0,
                records_after=1,
                history_unchanged_by_rejections=True,
            ),
        )
    )


def test_default_output_carries_narrative_history_and_a_verdict_per_service() -> None:
    stream = io.StringIO()

    render(_report(), stream, verbose=False)

    written = stream.getvalue()
    assert "semicolon" in written
    assert "check history before: 0 record(s)" in written
    assert "check history after : 1 record(s)" in written
    for expected in ("VULNERABLE", "STILL VULNERABLE", "SECURE"):
        assert expected in written
    assert written.count("VERDICT:") == 3
    assert RULE in written


def test_default_output_omits_the_http_exchange() -> None:
    stream = io.StringIO()

    render(_report(), stream, verbose=False)

    assert "body      :" not in stream.getvalue()


def test_verbose_output_adds_the_exchange_and_the_probe_output() -> None:
    stream = io.StringIO()

    render(_report(), stream, verbose=True)

    written = stream.getvalue()
    assert "body      :" in written
    assert "probe output:" in written


def test_every_rendering_shows_what_the_service_constructed() -> None:
    stream = io.StringIO()

    render(_report(), stream, verbose=False)

    assert stream.getvalue().count("constructed:") == 6


def test_the_parser_defaults_to_the_scripted_comparison() -> None:
    arguments = build_parser().parse_args([])

    assert arguments.interactive is False
    assert arguments.verbose is False


def test_the_parser_accepts_interactive_and_verbose() -> None:
    arguments = build_parser().parse_args(["--interactive", "--verbose"])

    assert arguments.interactive is True
    assert arguments.verbose is True
