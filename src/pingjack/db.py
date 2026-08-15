"""SQLite engine and session plumbing.

Each application run uses a fresh disposable database inside the container; nothing here reaches
outside the container's own filesystem.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pingjack.models import Base


def _is_memory(url: str) -> bool:
    return url in {"sqlite://", "sqlite:///:memory:"}


def create_database(url: str) -> Engine:
    """Create an engine for ``url`` and ensure the schema exists.

    Requests are served from a thread pool, so connections must be shareable across threads. An
    in-memory database additionally needs a single pooled connection, or each thread would silently
    get a database of its own.
    """
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False},
        **({"poolclass": StaticPool} if _is_memory(url) else {}),
    )
    Base.metadata.create_all(engine)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False)
