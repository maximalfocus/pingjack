"""Persistent shape of a check record.

Check records are append only: the storage layer offers no update or delete path, and nothing in
the product removes or rewrites a stored record.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for every persisted table."""


def new_check_id() -> str:
    """Return a fresh UUID string identifier.

    The identifier is an opaque handle for a record. It is not an access control: the API decides
    what an operator may read from the authenticated operator, never from the identifier's shape.
    """
    return str(uuid.uuid4())


class CheckRecord(Base):
    """One completed link check, owned by the fictional operator that submitted it."""

    __tablename__ = "check_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_check_id)
    operator_id: Mapped[str] = mapped_column(String(64), index=True)
    #: The host value exactly as submitted, retained verbatim so the demonstration can show what
    #: reached the server.
    host: Mapped[str] = mapped_column(Text)
    #: Everything the probe wrote to standard output.
    output: Mapped[str] = mapped_column(Text)
    exit_status: Mapped[int] = mapped_column(Integer)
