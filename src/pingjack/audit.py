"""Structured audit events on standard output.

A rejection is invisible to the client by design, so the server side is where it has to be
observable. These events are the only place the rejection class exists.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping

#: Submitted values are attacker chosen, so only a bounded, escaped rendering is ever recorded.
SUBMITTED_VALUE_CAP = 120


def render_submitted_value(value: str, cap: int = SUBMITTED_VALUE_CAP) -> dict[str, object]:
    """Return the length-capped, control-character-escaped rendering of a submitted value."""
    return {
        "submitted_value": value[:cap].encode("unicode_escape").decode("ascii"),
        "submitted_value_length": len(value),
        "submitted_value_truncated": len(value) > cap,
    }


def emit(event: Mapping[str, object]) -> None:
    """Write one JSON event, one line, to standard output."""
    sys.stdout.write(f"{json.dumps(dict(event), sort_keys=True)}\n")
    sys.stdout.flush()
