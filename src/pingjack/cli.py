"""The comparison CLI.

Scripted mode runs the whole comparison and prints a verdict per application. Interactive mode lets
you pick one application and one payload and watch what happens. All the reasoning lives in
``pingjack.scenario``; this module only parses arguments, asks questions, and prints.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from pingjack.auth import DEMO_TOKENS
from pingjack.gating import require_acknowledgement
from pingjack.harness import local_applications
from pingjack.scenario import (
    ARGUMENT_PAYLOAD,
    FLEET_HOST,
    METACHARACTER_PAYLOAD,
    NAIVE,
    SECURE,
    VULNERABLE,
    ApplicationResult,
    Report,
    constructed_invocation,
    run_scripted_comparison,
    submit,
)

DEMO_TOKEN = next(iter(DEMO_TOKENS))

RULE = "=" * 78

NARRATIVE = {
    VULNERABLE: (
        "The vulnerable service builds one command string and hands it to a shell. Watch what a "
        "semicolon does to a hostname field."
    ),
    NAIVE: (
        "The naive service uses no shell at all, so the payload above is inert here. That is the "
        "half fix - now watch the same file come back through an option instead."
    ),
    SECURE: (
        "The secure service validates the submitted value against a strict rule and the fleet "
        "allowlist before any process exists, then runs an argument vector. Both payloads are "
        "refused identically, and a legitimate check still works."
    ),
}

PAYLOAD_CHOICES = {
    "1": ("metacharacter injection", METACHARACTER_PAYLOAD),
    "2": ("argument injection", ARGUMENT_PAYLOAD),
    "3": ("a legitimate fleet host", FLEET_HOST),
}


def _print_result(result: ApplicationResult, stream: TextIO, *, verbose: bool) -> None:
    stream.write(f"\n{RULE}\n{result.application.upper()} service\n{RULE}\n")
    stream.write(f"{NARRATIVE[result.application]}\n\n")
    stream.write(f"check history before: {result.records_before} record(s)\n")

    for exchange in result.exchanges:
        stream.write(f"\n  submitted         : {exchange.submitted}\n")
        stream.write(f"  server constructed: {exchange.constructed}\n")
        stream.write(f"  response          : HTTP {exchange.status_code}\n")
        stream.write(f"  probe output      : {exchange.probe_summary}\n")
        stream.write(
            f"  check record      : {'created' if exchange.record_created else 'none created'}\n"
        )
        stream.write(f"  fixture disclosed : {'YES' if exchange.disclosed_fixture else 'no'}\n")
        if verbose:
            stream.write(f"  response body     : {exchange.body}\n")
            if exchange.output:
                indented = "\n".join(f"      {line}" for line in exchange.output.splitlines())
                stream.write(f"  probe output in full:\n{indented}\n")

    stream.write(f"\ncheck history after : {result.records_after} record(s)\n")
    if result.application == SECURE:
        unchanged = "yes" if result.history_unchanged_by_rejections else "NO"
        stream.write(f"history byte-for-byte unchanged by the rejections: {unchanged}\n")
    stream.write(f"\nVERDICT: {result.verdict}\n")


def render(report: Report, stream: TextIO, *, verbose: bool) -> None:
    """Write the whole comparison to ``stream``."""
    stream.write(
        "pingjack - the same submission, three services\n"
        "Everything below is fictional and runs only inside this container.\n"
    )
    for result in report.results:
        _print_result(result, stream, verbose=verbose)

    stream.write(f"\n{RULE}\nSUMMARY\n{RULE}\n")
    for result in report.results:
        stream.write(f"  {result.application:<11} {result.verdict}\n")
    stream.write(
        "\nRemoving the shell was necessary and not sufficient. Validating the input is what "
        "closed it.\n"
    )


def run_scripted(stream: TextIO, *, verbose: bool) -> int:
    """Run the full comparison against fresh state and report."""
    require_acknowledgement("demo")
    with local_applications() as clients:
        report = run_scripted_comparison(clients, DEMO_TOKEN)
    render(report, stream, verbose=verbose)
    if not report.demonstrates_every_outcome:
        stream.write("\nFAILED: the run did not demonstrate every expected outcome.\n")
        return 1
    return 0


def run_interactive(stream: TextIO, prompt: Callable[[str], str], *, verbose: bool) -> int:
    """Let the operator choose one application and one payload, then show the result."""
    require_acknowledgement("demo")
    applications = ", ".join((VULNERABLE, NAIVE, SECURE))
    choice = prompt(f"Which service? [{applications}] ").strip() or SECURE
    if choice not in {VULNERABLE, NAIVE, SECURE}:
        stream.write(f"Unknown service {choice!r}.\n")
        return 2

    stream.write("\nWhat would you like to submit?\n")
    for key, (label, payload) in PAYLOAD_CHOICES.items():
        stream.write(f"  {key}. {label}: {payload}\n")
    selected = prompt("Choice [1/2/3]: ").strip() or "1"
    if selected not in PAYLOAD_CHOICES:
        stream.write(f"Unknown choice {selected!r}.\n")
        return 2
    _, host = PAYLOAD_CHOICES[selected]

    stream.write(f"\n{choice} would construct: {constructed_invocation(choice, host)}\n")
    with local_applications() as clients:
        exchange = submit(clients[choice], choice, host, DEMO_TOKEN)
    stream.write(f"response  : HTTP {exchange.status_code}\n")
    stream.write(f"fixture disclosed: {'YES' if exchange.disclosed_fixture else 'no'}\n")
    if verbose:
        stream.write(f"body      : {exchange.body}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pingjack-demo",
        description="Compare the vulnerable, naive, and secure check services. Local only.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="choose one service and one payload instead of running the full comparison",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="also show the HTTP exchange and the probe output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``pingjack-demo`` console script."""
    arguments = build_parser().parse_args(argv)
    if arguments.interactive:
        return run_interactive(sys.stdout, input, verbose=arguments.verbose)
    return run_scripted(sys.stdout, verbose=arguments.verbose)


if __name__ == "__main__":  # pragma: no cover - exercised through the console script
    raise SystemExit(main())
