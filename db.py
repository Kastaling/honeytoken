"""Database engine and session for SQLAlchemy."""

import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from models import DATABASE_URL, Base

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
if DATABASE_URL.startswith("sqlite"):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=os.environ.get("SQL_ECHO", "").lower() in ("1", "true"),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
    """Run SQLite pragmas on the raw DB-API connection (not inside a SQLAlchemy transaction)."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


if DATABASE_URL.startswith("sqlite"):
    event.listen(engine, "connect", _configure_sqlite_connection)


def _ensure_sqlite_wal() -> None:
    """Enable WAL before schema work; journal_mode cannot change inside a transaction."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        mode = conn.execute(text("PRAGMA journal_mode=WAL")).scalar()
        if mode != "wal":
            raise RuntimeError(f"SQLite journal_mode is {mode!r}, expected 'wal'")


def init_db() -> None:
    _ensure_sqlite_wal()
    Base.metadata.create_all(bind=engine)
    existing_columns = {column["name"] for column in inspect(engine).get_columns("hits")}
    missing_columns = {
        "location_display": "VARCHAR(512)",
        "host": "VARCHAR(255)",
        "link_id": "INTEGER",
        # This is a SQL column type, not a hard-coded credential.
        "capture_token": "VARCHAR(128)",  # nosec B105
        "visitor_fp_id": "VARCHAR(64)",
    }
    with engine.begin() as conn:
        for name, sql_type in missing_columns.items():
            if name not in existing_columns:
                logger.info("Adding database column hits.%s", name)
                conn.execute(text(f"ALTER TABLE hits ADD COLUMN {name} {sql_type}"))
        for stmt in (
            "CREATE INDEX IF NOT EXISTS ix_hits_link_id ON hits (link_id)",
            "CREATE INDEX IF NOT EXISTS ix_hits_created_at ON hits (created_at)",
            "CREATE INDEX IF NOT EXISTS ix_hits_visitor_fp_id ON hits (visitor_fp_id)",
            "CREATE INDEX IF NOT EXISTS ix_tracked_links_token ON tracked_links (token)",
            "CREATE INDEX IF NOT EXISTS ix_tracked_links_host ON tracked_links (host)",
        ):
            conn.execute(text(stmt))


def get_session() -> Session:
    return SessionLocal()
