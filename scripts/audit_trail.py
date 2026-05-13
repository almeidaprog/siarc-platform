"""
Audit Trail — SIARC Sprint Maio/2026

Trilha de auditoria append-only conforme LGPD Art. 37:
"O controlador ou operador que, em razão do exercício de atividade de tratamento
de dados pessoais, causar a outrem dano patrimonial, moral, individual ou coletivo,
é obrigado a repará-lo."

O registro imutável garante rastreabilidade e responsabilização.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_AUDIT_LOG_PATH = Path("data/audit_log.jsonl")


# ---------------------------------------------------------------------------
# Escrita na trilha
# ---------------------------------------------------------------------------

def _ensure_dir() -> None:
    _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def record(
    event_id: str,
    action: str,
    actor: str = "siarc-api",
    outcome: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Registra uma entrada na trilha de auditoria.

    Parâmetros:
        event_id  — ID único do evento analisado
        action    — ação executada (ex: LGPD_SANITIZATION, RISK_ASSESSMENT)
        actor     — componente ou usuário que executou a ação
        outcome   — SUCCESS | FAILURE | PARTIAL
        details   — metadados adicionais (não contém dados pessoais)
    """
    _ensure_dir()
    entry: Dict[str, Any] = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": event_id,
        "action": action,
        "actor": actor,
        "outcome": outcome,
        "lgpd_reference": "Lei 13.709/2018 — Art. 37 (Registro de Operações de Tratamento)",
        "details": details or {},
    }
    with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


# ---------------------------------------------------------------------------
# Leitura e consulta
# ---------------------------------------------------------------------------

def _load_entries() -> List[Dict[str, Any]]:
    _ensure_dir()
    if not _AUDIT_LOG_PATH.exists():
        return []
    entries: List[Dict[str, Any]] = []
    for line in _AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def get_recent(limit: int = 20) -> List[Dict[str, Any]]:
    """Retorna as `limit` entradas mais recentes, da mais nova para a mais antiga."""
    entries = _load_entries()
    return list(reversed(entries[-limit:]))


def get_by_event(event_id: str) -> List[Dict[str, Any]]:
    """Retorna todas as entradas de auditoria associadas a um event_id."""
    return [e for e in _load_entries() if e.get("event_id") == event_id]


def get_summary() -> Dict[str, Any]:
    """Gera um resumo estatístico da trilha de auditoria."""
    entries = _load_entries()
    by_outcome: Dict[str, int] = {}
    by_action: Dict[str, int] = {}
    by_actor: Dict[str, int] = {}

    for e in entries:
        outcome = e.get("outcome", "UNKNOWN")
        action = e.get("action", "UNKNOWN")
        actor = e.get("actor", "UNKNOWN")
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        by_action[action] = by_action.get(action, 0) + 1
        by_actor[actor] = by_actor.get(actor, 0) + 1

    first_ts = entries[0].get("audit_timestamp") if entries else None
    last_ts = entries[-1].get("audit_timestamp") if entries else None

    return {
        "total_entries": len(entries),
        "first_entry": first_ts,
        "last_entry": last_ts,
        "by_outcome": by_outcome,
        "by_action": by_action,
        "by_actor": by_actor,
        "lgpd_compliance": "Art. 37 — Registro de operações mantido e disponível.",
    }
