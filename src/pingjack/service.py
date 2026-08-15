"""The shared service layer.

Authentication, persistence, the HTTP contract, and the rejection audit event are identical in all
three applications. Each application supplies only an executor: the function that turns a submitted
value into an invocation and runs it.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.base import RequestResponseEndpoint

from pingjack import audit
from pingjack.auth import CurrentOperator
from pingjack.db import create_database, session_factory
from pingjack.execution import CheckOutcome, RejectedCheck
from pingjack.models import CheckRecord
from pingjack.storage import append_check_record, list_check_records

DATABASE_URL_ENV = "PINGJACK_DATABASE_URL"
DEFAULT_DATABASE_URL = "sqlite://"

#: One generic body for every refused submission, identical for every rejection class.
REJECTION_DETAIL = "check request rejected"

REQUEST_ID_HEADER = "X-Request-ID"

CheckExecutor = Callable[[str], CheckOutcome]


class CheckRequest(BaseModel):
    """A submitted check. The host is accepted as-is; what happens next is the application's job."""

    host: str


class CheckOut(BaseModel):
    """A stored check record as the API returns it."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    host: str
    output: str
    exit_status: int


def _request_id(request: Request) -> str:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else str(uuid.uuid4())


def _session(request: Request) -> Iterator[Session]:
    """Yield a session from the running application's own factory."""
    sessions: sessionmaker[Session] = request.app.state.sessions
    with sessions() as session:
        yield session


SessionDep = Annotated[Session, Depends(_session)]


def create_app(*, executor: CheckExecutor, title: str, summary: str) -> FastAPI:
    """Build one application around ``executor``."""
    engine = create_database(os.environ.get(DATABASE_URL_ENV, DEFAULT_DATABASE_URL))

    app = FastAPI(title=title, summary=summary, version="0.1.0")
    app.state.sessions = session_factory(engine)

    @app.middleware("http")
    async def _correlate(request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request.state.request_id
        return response

    @app.post("/checks", status_code=status.HTTP_201_CREATED, response_model=CheckOut)
    def submit_check(
        payload: CheckRequest,
        operator: CurrentOperator,
        session: SessionDep,
        request: Request,
    ) -> CheckRecord:
        outcome = executor(payload.host)
        if isinstance(outcome, RejectedCheck):
            audit.emit(
                {
                    "event": "check.rejected",
                    "request_id": _request_id(request),
                    "operator_id": operator.id,
                    "action": "check.submit",
                    "outcome": "rejected",
                    "rejection_class": outcome.rejection_class.value,
                    **audit.render_submitted_value(payload.host),
                }
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=REJECTION_DETAIL)
        return append_check_record(
            session,
            operator_id=operator.id,
            host=payload.host,
            output=outcome.output,
            exit_status=outcome.exit_status,
        )

    @app.get("/checks", response_model=list[CheckOut])
    def read_checks(operator: CurrentOperator, session: SessionDep) -> list[CheckRecord]:
        return list_check_records(session, operator_id=operator.id)

    return app
