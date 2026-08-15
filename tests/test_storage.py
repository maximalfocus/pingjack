"""Check records are UUID identified, operator scoped, and append only."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy.orm import Session

import pingjack.storage as storage
from pingjack.db import create_database, session_factory


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_database("sqlite://")
    factory = session_factory(engine)
    with factory() as open_session:
        yield open_session
    engine.dispose()


def test_appending_retains_every_field(session: Session) -> None:
    record = storage.append_check_record(
        session,
        operator_id="operator-alpha",
        host="relay-7.internal.test",
        output="fleetprobe 1.0 :: ...",
        exit_status=0,
    )

    assert uuid.UUID(record.id).version == 4
    assert record.operator_id == "operator-alpha"
    assert record.host == "relay-7.internal.test"
    assert record.output == "fleetprobe 1.0 :: ..."
    assert record.exit_status == 0


def test_the_submitted_host_value_is_retained_verbatim(session: Session) -> None:
    submitted = "relay-7.internal.test; cat /srv/netops/fleet_deploy.key"

    record = storage.append_check_record(
        session, operator_id="operator-alpha", host=submitted, output="", exit_status=0
    )

    assert record.host == submitted


def test_listing_returns_only_the_owning_operators_records(session: Session) -> None:
    storage.append_check_record(
        session,
        operator_id="operator-alpha",
        host="relay-7.internal.test",
        output="",
        exit_status=0,
    )
    storage.append_check_record(
        session,
        operator_id="operator-bravo",
        host="relay-8.internal.test",
        output="",
        exit_status=0,
    )

    alpha = storage.list_check_records(session, operator_id="operator-alpha")

    assert [record.host for record in alpha] == ["relay-7.internal.test"]


def test_repeat_submissions_append_independent_records(session: Session) -> None:
    first = storage.append_check_record(
        session,
        operator_id="operator-alpha",
        host="relay-7.internal.test",
        output="",
        exit_status=0,
    )
    second = storage.append_check_record(
        session,
        operator_id="operator-alpha",
        host="relay-7.internal.test",
        output="",
        exit_status=0,
    )

    assert first.id != second.id
    assert len(storage.list_check_records(session, operator_id="operator-alpha")) == 2


def test_storage_exposes_no_update_or_delete_path() -> None:
    public = {name for name in vars(storage) if not name.startswith("_")}

    assert {"append_check_record", "list_check_records"} <= public
    assert not any(
        verb in name for name in public for verb in ("delete", "remove", "update", "purge", "drop")
    )
