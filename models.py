"""SQLAlchemy schema for hits and generated tracking links."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "honey.db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Hit(Base):
    __tablename__ = "hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    host = Column(String(255), nullable=True)  # Host or X-Forwarded-Host at request time
    path = Column(String(2048), nullable=False)
    method = Column(String(16), nullable=False)
    headers = Column(Text, nullable=True)  # JSON
    fingerprint = Column(Text, nullable=True)  # JSON
    query_string = Column(String(2048), nullable=True)
    location = Column(Text, nullable=True)  # JSON (country, region, city, isp from ip-api)
    location_display = Column(String(512), nullable=True)  # Formatted "City, Region, Country" from GeoIP2
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    city = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=_utc_now_naive)
    client_fingerprint = Column(Text, nullable=True)  # JSON
    visitor_fp_id = Column(String(64), nullable=True, index=True)
    link_id = Column(Integer, nullable=True, index=True)
    capture_token = Column(String(128), nullable=True)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "_ts": self.created_at.isoformat() + "Z" if self.created_at else None,
            "ip": self.ip,
            "host": self.host,
            "path": self.path,
            "method": self.method,
            "headers": json.loads(self.headers) if self.headers else {},
            "fingerprint": json.loads(self.fingerprint) if self.fingerprint else {},
            "query_string": self.query_string,
            "location": json.loads(self.location) if self.location else {},
            "location_display": self.location_display,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "city": self.city,
            "client_fingerprint": json.loads(self.client_fingerprint) if self.client_fingerprint else {},
            "visitor_fp_id": self.visitor_fp_id,
            "link_id": self.link_id,
            "capture_token": self.capture_token,
        }


class TrackedLink(Base):
    __tablename__ = "tracked_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(96), nullable=False, unique=True, index=True)
    host = Column(String(255), nullable=False, index=True)
    path = Column(String(255), nullable=False)
    label = Column(String(200), nullable=True)
    settings = Column(Text, nullable=False)  # JSON final-action settings
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    updated_at = Column(DateTime, default=_utc_now_naive, onupdate=_utc_now_naive, nullable=False)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "token": self.token,
            "host": self.host,
            "path": self.path,
            "label": self.label or "",
            "settings": json.loads(self.settings) if self.settings else {},
            "active": bool(self.active),
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "updated_at": self.updated_at.isoformat() + "Z" if self.updated_at else None,
        }
