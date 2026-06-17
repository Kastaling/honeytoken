"""Database engine and session for SQLAlchemy."""
import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from models import Base, DATABASE_URL

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
if DATABASE_URL.startswith("sqlite"):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=os.environ.get("SQL_ECHO", "").lower() in ("1", "true"),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Add location_display column if it doesn't exist (existing DBs)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE hits ADD COLUMN location_display VARCHAR(512)"))
            conn.commit()
    except Exception:
        pass
    # Add host column if it doesn't exist (existing DBs)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE hits ADD COLUMN host VARCHAR(255)"))
            conn.commit()
    except Exception:
        pass
    # Add generated-link attribution columns if they don't exist (existing DBs)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE hits ADD COLUMN link_id INTEGER"))
            conn.commit()
    except Exception:
        pass
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE hits ADD COLUMN capture_token VARCHAR(128)"))
            conn.commit()
    except Exception:
        pass
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE hits ADD COLUMN visitor_fp_id VARCHAR(64)"))
            conn.commit()
    except Exception:
        pass
    # Helpful indexes for pagination/filtering/stats. IF NOT EXISTS works on SQLite/Postgres.
    for stmt in (
        "CREATE INDEX IF NOT EXISTS ix_hits_link_id ON hits (link_id)",
        "CREATE INDEX IF NOT EXISTS ix_hits_created_at ON hits (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_hits_visitor_fp_id ON hits (visitor_fp_id)",
        "CREATE INDEX IF NOT EXISTS ix_tracked_links_token ON tracked_links (token)",
        "CREATE INDEX IF NOT EXISTS ix_tracked_links_host ON tracked_links (host)",
    ):
        try:
            with engine.connect() as conn:
                conn.execute(text(stmt))
                conn.commit()
        except Exception:
            pass


def get_session() -> Session:
    return SessionLocal()
