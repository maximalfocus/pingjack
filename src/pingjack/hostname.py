"""The strict hostname syntax rule.

This is an allowlist of shape: a value is acceptable only when every character of every label is
one the rule permits. It is not a denylist of shell metacharacters - a denylist has to anticipate
every dangerous character, while this rule rejects everything it was not written to accept.
"""

from __future__ import annotations

import re

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

#: One label: lowercase letters, digits, and interior hyphens only.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def is_valid_hostname(value: str) -> bool:
    """Return whether ``value`` matches the strict hostname syntax rule."""
    if not value or len(value) > MAX_HOSTNAME_LENGTH:
        return False
    labels = value.split(".")
    return all(
        0 < len(label) <= MAX_LABEL_LENGTH and _LABEL.match(label) is not None for label in labels
    )
