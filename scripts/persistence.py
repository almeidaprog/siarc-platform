"""Database-backed audit persistence.

Docker deployment uses PostgreSQL via DATABASE_URL. For local unit tests and
portable development, SQLite is supported by setting DATABASE_URL accordingly.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, select, func, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


class Base(DeclarativeBase):
    pass


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    lgpd_reference: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


def _database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "sqlite:///data/siarc_audit.db",
    )


_engine = None
_engine_url = None


def get_engine():
    global _engine, _engine_url
    url = _database_url()
    if _engine is None or _engine_url != url:
        kwargs = {"pool_pre_ping": True, "future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 60}
        _engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=60000")
                cursor.close()
        _engine_url = url
    return _engine


def init_db() -> None:
    Base.metadata.create_all(get_engine())


def insert_audit(entry: Dict[str, Any]) -> None:
    init_db()
    ts = entry.get("audit_timestamp")
    if isinstance(ts, str):
        ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    else:
        ts_dt = ts or datetime.now(timezone.utc)
    row = AuditEntry(
        audit_timestamp=ts_dt,
        event_id=str(entry["event_id"]),
        action=str(entry["action"]),
        actor=str(entry.get("actor", "siarc-api")),
        outcome=str(entry.get("outcome", "SUCCESS")),
        lgpd_reference=str(entry.get("lgpd_reference", "")),
        details=entry.get("details") or {},
    )
    with Session(get_engine()) as session:
        session.add(row)
        session.commit()


def recent(limit: int = 20) -> List[Dict[str, Any]]:
    init_db()
    with Session(get_engine()) as session:
        rows = session.scalars(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)).all()
        return [_to_dict(r) for r in rows]


def by_event(event_id: str) -> List[Dict[str, Any]]:
    init_db()
    with Session(get_engine()) as session:
        rows = session.scalars(select(AuditEntry).where(AuditEntry.event_id == event_id).order_by(AuditEntry.id)).all()
        return [_to_dict(r) for r in rows]


def summary() -> Dict[str, Any]:
    init_db()
    with Session(get_engine()) as session:
        total = session.scalar(select(func.count()).select_from(AuditEntry)) or 0
        rows = session.scalars(select(AuditEntry).order_by(AuditEntry.id)).all()
    by_outcome: Dict[str, int] = {}
    by_action: Dict[str, int] = {}
    by_actor: Dict[str, int] = {}
    for r in rows:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        by_action[r.action] = by_action.get(r.action, 0) + 1
        by_actor[r.actor] = by_actor.get(r.actor, 0) + 1
    return {
        "total_entries": total,
        "first_entry": rows[0].audit_timestamp.isoformat() if rows else None,
        "last_entry": rows[-1].audit_timestamp.isoformat() if rows else None,
        "by_outcome": by_outcome,
        "by_action": by_action,
        "by_actor": by_actor,
        "backend": _database_url().split(":", 1)[0],
        "lgpd_compliance": "Art. 37 - processing-operation records retained and queryable.",
    }


def _to_dict(r: AuditEntry) -> Dict[str, Any]:
    return {
        "audit_timestamp": r.audit_timestamp.isoformat(),
        "event_id": r.event_id,
        "action": r.action,
        "actor": r.actor,
        "outcome": r.outcome,
        "lgpd_reference": r.lgpd_reference,
        "details": r.details or {},
    }
