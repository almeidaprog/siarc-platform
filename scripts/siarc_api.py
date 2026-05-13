"""
SIARC API — Sprint Maio/2026

Endpoints disponíveis:
  GET  /health                  — verificação de saúde
  POST /analyze                 — análise completa com LGPD + risco XAI + auditoria
  GET  /governance/policies     — políticas de governança ativas
  GET  /governance/report       — relatório de conformidade LGPD
  GET  /audit/entries           — entradas recentes da trilha de auditoria
  GET  /audit/summary           — resumo estatístico da trilha
"""
import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from scripts.lgpd_engine import apply_lgpd_governance, LegalBasis
from scripts.risk_engine import calculate_risk
from scripts import audit_trail

app = FastAPI(
    title="SIARC — Sistema Inteligente de Auditoria e Resiliência Cibernética",
    description=(
        "API de governança de dados e análise de risco cibernético. "
        "Implementa conformidade LGPD (Lei 13.709/2018) com trilha de auditoria e scoring XAI."
    ),
    version="0.2.0",
)

_POLICIES_PATH = Path("data/governance_policies.json")


# ---------------------------------------------------------------------------
# Modelos de entrada
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    timestamp: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    event_type: str = "unknown"
    severity: str = "low"
    payload: str = ""
    extra: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "siarc-api", "version": "0.2.0"}


@app.post(
    "/analyze",
    summary="Análise completa: LGPD + risco XAI + auditoria",
    response_description="Evento sanitizado com score de risco e decisão de governança",
)
def analyze(event: SecurityEvent) -> Dict[str, Any]:
    """
    Pipeline completo de análise de um evento de segurança:

    1. Aplica governança LGPD (sanitização de PII, avaliação dos 10 princípios Art. 6)
    2. Calcula score de risco multifatorial com explicações XAI
    3. Registra operação na trilha de auditoria (Art. 37)
    4. Retorna evento sanitizado + decisão de governança + avaliação de risco
    """
    event_id = str(uuid.uuid4())
    raw = event.model_dump()

    # ── 1. Governança LGPD ────────────────────────────────────────────────
    sanitized, gov_decision = apply_lgpd_governance(
        raw,
        event_id=event_id,
        legal_basis=LegalBasis.SECURITY_RESEARCH,
        purpose="Auditoria de segurança cibernética — SIARC",
    )

    # ── 2. Avaliação de risco (sobre os dados originais, antes de sanitizar) ──
    risk = calculate_risk(raw)

    # ── 3. Trilha de auditoria ────────────────────────────────────────────
    audit_trail.record(
        event_id=event_id,
        action="FULL_ANALYSIS",
        outcome="SUCCESS",
        details={
            "event_type": raw.get("event_type"),
            "severity": raw.get("severity"),
            "pii_count": len(gov_decision.pii_detected),
            "risk_score": risk.score,
            "risk_level": risk.level,
            "compliance_status": gov_decision.compliance_status,
        },
    )

    return {
        "event_id": event_id,
        "sanitized_event": sanitized,
        "governance": gov_decision.to_dict(),
        "risk_assessment": risk.to_dict(),
    }


@app.get(
    "/governance/policies",
    summary="Lista políticas de governança ativas",
)
def list_policies() -> Dict[str, Any]:
    if not _POLICIES_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo de políticas não encontrado.")
    return json.loads(_POLICIES_PATH.read_text(encoding="utf-8"))


@app.get(
    "/governance/report",
    summary="Relatório de conformidade LGPD",
)
def governance_report() -> Dict[str, Any]:
    summary = audit_trail.get_summary()
    recent = audit_trail.get_recent(limit=5)

    total = summary.get("total_entries", 0)
    successes = summary.get("by_outcome", {}).get("SUCCESS", 0)
    compliance_rate = round((successes / total * 100) if total else 0.0, 1)

    return {
        "report_title": "Relatório de Conformidade LGPD — SIARC",
        "legal_basis": "Lei 13.709/2018",
        "audit_summary": summary,
        "compliance_rate_pct": compliance_rate,
        "recent_operations": recent,
        "principles_reference": "Art. 6 — Finalidade, Adequação, Necessidade, Livre Acesso, "
                                "Qualidade, Transparência, Segurança, Prevenção, "
                                "Não Discriminação, Responsabilização",
    }


@app.get(
    "/audit/entries",
    summary="Entradas recentes da trilha de auditoria (LGPD Art. 37)",
)
def audit_entries(limit: int = Query(default=20, ge=1, le=100)) -> Dict[str, Any]:
    entries = audit_trail.get_recent(limit=limit)
    return {
        "lgpd_reference": "Art. 37 — Registro de Operações de Tratamento",
        "count": len(entries),
        "entries": entries,
    }


@app.get(
    "/audit/summary",
    summary="Resumo estatístico da trilha de auditoria",
)
def audit_summary() -> Dict[str, Any]:
    return audit_trail.get_summary()
