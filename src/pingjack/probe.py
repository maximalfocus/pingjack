"""The bundled fleet link check utility.

The demonstration ships its own probe instead of invoking a system network tool, so that the
observable output is fully determined by the arguments and by the named ``--config`` file. The
utility performs no network access, reads no clock, and uses no randomness: identical arguments
always produce identical bytes.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pingjack.fleet import is_fleet_host

#: Name of the installed console script. Callers resolve the probe through this constant so that
#: the executable can never be chosen by request data or configuration.
PROBE_COMMAND = "fleetprobe"

BANNER = "fleetprobe 1.0 :: Meridian Fleet Operations link check"

EXIT_REACHABLE = 0
EXIT_UNREACHABLE = 1


def _render_config_line(path: str) -> str:
    """Echo the contents of ``path`` on a single line.

    ``--config`` is a deliberate operational affordance: a real fleet tool would plausibly accept a
    profile file, and the naive application's argument injection demonstration depends on that
    plausibility. Contents are collapsed onto one line so the output stays a fixed line shape.
    """
    try:
        contents = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"config[{path}]: (unreadable)"
    return f"config[{path}]: {' '.join(contents.split())}"


def build_report(host: str, count: int, config: str | None) -> tuple[list[str], int]:
    """Return the probe's output lines and its exit status.

    A fleet member yields ``count`` result lines and :data:`EXIT_REACHABLE`; anything else - an
    unknown host, or no host at all - yields a single unreachable line and :data:`EXIT_UNREACHABLE`.
    """
    lines = [BANNER]
    if config is not None:
        lines.append(_render_config_line(config))
    if is_fleet_host(host):
        lines.extend(
            f"reply from {host}: seq={seq} bytes=64 status=ok" for seq in range(1, count + 1)
        )
        return lines, EXIT_REACHABLE
    lines.append(f'no reply from "{host}": link check failed')
    return lines, EXIT_UNREACHABLE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROBE_COMMAND,
        description="Check a fictional fleet host. Performs no network access.",
    )
    parser.add_argument("--count", type=int, default=1, help="number of result lines to emit")
    parser.add_argument("--config", default=None, help="operational profile file to echo")
    # The host is optional so that an argument-only invocation still produces a report rather than
    # a usage error. That keeps the utility's behaviour uniform for every caller.
    parser.add_argument("host", nargs="?", default="", help="host to check")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the probe. Returns the process exit status."""
    args = _parser().parse_args(argv)
    count = max(args.count, 0)
    lines, status = build_report(args.host, count, args.config)
    sys.stdout.write("".join(f"{line}\n" for line in lines))
    return status


if __name__ == "__main__":  # pragma: no cover - exercised through the console script
    raise SystemExit(main())
