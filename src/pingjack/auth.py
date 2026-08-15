"""Demonstration-only bearer authentication.

The tokens below are constants in a public educational repository. They are unmistakably fake, they
protect nothing, and they exist only so the demonstration has an authenticated operator to attribute
a check to.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pingjack.fleet import Operator, find_operator

#: Fictional operator credentials. Not secrets, and never treated as any kind of protection.
DEMO_TOKENS: dict[str, str] = {
    "demo-token-alpha-not-a-real-secret": "operator-alpha",
    "demo-token-bravo-not-a-real-secret": "operator-bravo",
}

#: One generic body for every authentication failure, so a caller cannot learn whether a token was
#: absent, malformed, or simply unknown.
UNAUTHORIZED_DETAIL = "unauthorized"
BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}

_bearer = HTTPBearer(auto_error=False)


def resolve_operator(token: str | None) -> Operator | None:
    """Return the fictional operator a token belongs to, or ``None``."""
    if token is None:
        return None
    operator_id = DEMO_TOKENS.get(token)
    return None if operator_id is None else find_operator(operator_id)


def require_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Operator:
    """Resolve the calling operator, or fail with the one generic 401."""
    operator = resolve_operator(credentials.credentials if credentials is not None else None)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=UNAUTHORIZED_DETAIL,
            headers=BEARER_CHALLENGE,
        )
    return operator


CurrentOperator = Annotated[Operator, Depends(require_operator)]
