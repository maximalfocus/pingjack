"""Append only access to check records.

This module is deliberately the whole storage surface: it can append a record and read an
operator's own records, and it offers no way to update or delete one.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from pingjack.models import CheckRecord


def append_check_record(
    session: Session,
    *,
    operator_id: str,
    host: str,
    output: str,
    exit_status: int,
) -> CheckRecord:
    """Append one check record and return it."""
    record = CheckRecord(
        operator_id=operator_id,
        host=host,
        output=output,
        exit_status=exit_status,
    )
    session.add(record)
    session.commit()
    return record


def list_check_records(session: Session, *, operator_id: str) -> list[CheckRecord]:
    """Return every record owned by ``operator_id``, oldest first, and nobody else's."""
    statement = (
        select(CheckRecord).where(CheckRecord.operator_id == operator_id).order_by(CheckRecord.id)
    )
    return list(session.scalars(statement))
