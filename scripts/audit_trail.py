"""SIARC audit trail persisted through the configured SQL database."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scripts.persistence import insert_audit, recent, by_event, summary


def record(
    event_id: str,
    action: str,
    actor: str = "siarc-api",
    outcome: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": event_id,
        "action": action,
        "actor": actor,
        "outcome": outcome,
        "lgpd_reference": "Lei 13.709/2018 - Art. 37 (registro das operacoes de tratamento)",
        "details": details or {},
    }
    insert_audit(entry)
    return entry


def get_recent(limit: int = 20) -> List[Dict[str, Any]]:
    return recent(limit)


def get_by_event(event_id: str) -> List[Dict[str, Any]]:
    return by_event(event_id)


def get_summary() -> Dict[str, Any]:
    return summary()
