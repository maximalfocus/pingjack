"""SQLite engine and session plumbing.

Each application run uses a fresh disposable database inside the container; nothing here reaches
outside the container's own filesystem.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from pingjack.models import Base


def create_database(url: str) -> Engine:
    """Create an engine for ``url`` and ensure the schema exists."""
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to ``engine``."""
    return sessionmaker(bind=engine, expire_on_commit=False)
