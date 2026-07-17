"""
API principal do SIARC

Endpoints disponíveis:
  GET  /health                     — verificação de saúde
  POST /analyze                    — análise completa com LGPD + risco XAI + auditoria
  POST /analyze/exploit            — análise especializada de exploits e malwares mutáveis
  POST /analyze/exploit/batch      — análise em lote com correlação entre eventos
  GET  /exploit/history            — eventos recentes no histórico da janela deslizante
  GET  /governance/policies        — políticas de governança ativas
  GET  /governance/report          — relatório de conformidade LGPD
  GET  /audit/entries              — entradas recentes da trilha de auditoria
  GET  /audit/summary              — resumo estatístico da trilha
"""
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from scripts.lgpd_engine import apply_lgpd_governance, LegalBasis
from scripts.risk_engine import calculate_risk
from scripts.active_response import build_active_response
from scripts.exploit_analyzer import (
    analyze_exploit,
    push_to_history,
    _get_window_events,
)
from scripts import audit_trail

app = FastAPI(
    title="SIARC — Sistema Inteligente de Auditoria e Resiliência Cibernética",
    description=(
        "API de governança de dados e análise de risco cibernético. "
        "Implementa conformidade LGPD (Lei 13.709/2018), scoring XAI, "
        "trilha de auditoria e análise especializada de exploits (Sprint Junho/2026)."
    ),
    version="0.4.0",
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


class ExploitEvent(BaseModel):
    timestamp: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    event_type: str = "unknown"
    severity: str = "low"
    payload: str = ""
    extra: Optional[Dict[str, Any]] = None
    window_seconds: int = 300   # janela de correlação temporal em segundos


class ExploitBatchRequest(BaseModel):
    events: List[ExploitEvent]
    window_seconds: int = 300


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "siarc-api", "version": "0.4.0"}


@app.post(
    "/analyze",
    summary="Análise de evento com LGPD, score e auditoria",
    response_description="Evento sanitizado com score de risco e decisão de governança",
)
def analyze(event: SecurityEvent) -> Dict[str, Any]:
    """
    Fluxo usado para analisar um evento de segurança:

    1. Aplica governança LGPD (sanitização de PII, avaliação dos 10 princípios Art. 6)
    2. Calcula score de risco multifatorial com explicações XAI
    3. Registra operação na trilha de auditoria (Art. 37)
    4. Retorna evento sanitizado + decisão de governança + avaliação de risco
    """
    event_id = str(uuid.uuid4())
    raw = event.model_dump()

    # ── 1. Tratamento LGPD ────────────────────────────────────────────────
    sanitized, gov_decision = apply_lgpd_governance(
        raw,
        event_id=event_id,
        legal_basis=LegalBasis.SECURITY_RESEARCH,
        purpose="Auditoria de segurança cibernética — SIARC",
    )

    # ── 2. Cálculo do score de risco ──
    risk = calculate_risk(raw)

    # ── 3. Resposta simulada ───────────────────────────────────────
    active_response = build_active_response(
        score=risk.score,
        risk_level=risk.level,
        target_ip=raw.get("src_ip"),
        event_id=event_id,
    )

    # ── 4. Registro de auditoria ────────────────────────────────────────────
    audit_trail.record(
        event_id=event_id,
        action="FULL_ANALYSIS_AND_ACTIVE_RESPONSE",
        outcome="SUCCESS",
        details={
            "event_type": raw.get("event_type"),
            "severity": raw.get("severity"),
            "pii_count": len(gov_decision.pii_detected),
            "risk_score": risk.score,
            "risk_level": risk.level,
            "recommended_action": risk.recommended_action,
            "active_response_action": active_response["action"],
            "active_response_status": active_response["status"],
            "target_ip": raw.get("src_ip"),
            "compliance_status": gov_decision.compliance_status,
        },
    )

    return {
        "event_id": event_id,
        "score": risk.score,
        "risk_level": risk.level,
        "recommended_action": risk.recommended_action,
        "active_response": active_response,
        "sanitized_event": sanitized,
        "governance": gov_decision.to_dict(),
        "risk_assessment": risk.to_dict(),
    }


@app.post(
    "/analyze/exploit",
    summary="Análise de exploit e correlação de eventos",
    response_description="Perfil de exploit com técnicas detectadas, score e veredito",
)
def analyze_exploit_endpoint(event: ExploitEvent) -> Dict[str, Any]:
    """
    Fluxo usado nos testes de exploits:

    1. Extrai CVEs por regex (CVE-YYYY-NNNNN)
    2. Classifica técnicas de exploit em 18 categorias com mapeamento MITRE ATT&CK
    3. Detecta comportamento polimórfico/metamórfico
    4. Detecta indicadores de zero-day
    5. Fingerprinting comportamental por cadeia de ataque (histórico da janela)
    6. Correlação temporal (eventos do mesmo IP na janela de tempo)
    7. Calcula exploit_score 0-100 com explicações XAI
    8. Emite veredito: LIMPO | SUSPEITO | EXPLOIT_CONFIRMADO | EXPLOIT_CRITICO
    9. Registra na trilha de auditoria e adiciona ao histórico de correlação
    """
    event_id = str(uuid.uuid4())
    raw = event.model_dump(exclude={"window_seconds"})

    # ── 1. Análise de exploit ─────────────────────────────────────────────
    profile = analyze_exploit(
        raw,
        window_seconds=event.window_seconds,
        event_id=event_id,
    )

    # ── 2. Resposta simulada para o resultado do exploit ─────────────────────────
    active_response = build_active_response(
        score=profile.exploit_score,
        risk_level="CRÍTICO" if profile.exploit_score >= 80 else ("ALTO" if profile.exploit_score >= 60 else ("MÉDIO" if profile.exploit_score >= 30 else "BAIXO")),
        target_ip=raw.get("src_ip"),
        event_id=event_id,
        is_zero_day=profile.is_zero_day,
        verdict=profile.verdict.value,
    )

    # ── 3. Guarda o evento para correlação com os próximos ────────
    push_to_history(raw)

    # ── 4. Registro de auditoria ────────────────────────────────────────────
    audit_trail.record(
        event_id=event_id,
        action="EXPLOIT_ANALYSIS",
        outcome="SUCCESS",
        details={
            "event_type": raw.get("event_type"),
            "severity": raw.get("severity"),
            "exploit_score": profile.exploit_score,
            "verdict": profile.verdict.value,
            "techniques_count": len(profile.techniques_detected),
            "cves_found": profile.cves_found,
            "is_zero_day": profile.is_zero_day,
            "is_polymorphic": profile.is_polymorphic,
            "behavioral_signatures": len(profile.behavioral_signatures),
            "active_response_action": active_response["action"],
            "active_response_status": active_response["status"],
        },
    )

    return {
        "event_id": event_id,
        "score": profile.exploit_score,
        "risk_level": "CRÍTICO" if profile.exploit_score >= 80 else ("ALTO" if profile.exploit_score >= 60 else ("MÉDIO" if profile.exploit_score >= 30 else "BAIXO")),
        "recommended_action": active_response["action"],
        "active_response": active_response,
        "exploit_analysis": profile.to_dict(),
    }


@app.post(
    "/analyze/exploit/batch",
    summary="Análise em lote de exploits com correlação cruzada entre eventos",
    response_description="Lista de perfis de exploit analisados com correlação entre eventos",
)
def analyze_exploit_batch(request: ExploitBatchRequest) -> Dict[str, Any]:
    """
    Analisa uma lista de eventos em lote, com correlação cruzada completa.

    Vantagem sobre chamadas individuais: todos os eventos da lista são
    usados como histórico uns dos outros, maximizando a detecção de
    cadeias de ataque comportamentais (APT kill chain, ransomware chain, etc.).
    """
    results = []
    event_list = [e.model_dump(exclude={"window_seconds"}) for e in request.events]

    for i, raw in enumerate(event_list):
        event_id = str(uuid.uuid4())

        # Usa os eventos anteriores do batch como histórico
        history_for_this = event_list[:i]

        profile = analyze_exploit(
            raw,
            event_history=history_for_this,
            window_seconds=request.window_seconds,
            event_id=event_id,
        )
        push_to_history(raw)

        audit_trail.record(
            event_id=event_id,
            action="EXPLOIT_BATCH_ANALYSIS",
            outcome="SUCCESS",
            details={
                "batch_position": i,
                "event_type": raw.get("event_type"),
                "exploit_score": profile.exploit_score,
                "verdict": profile.verdict.value,
                "cves_found": profile.cves_found,
            },
        )

        results.append({
            "event_id": event_id,
            "exploit_analysis": profile.to_dict(),
        })

    critical_count = sum(
        1 for r in results
        if r["exploit_analysis"]["verdict"] in ("EXPLOIT_CRITICO", "EXPLOIT_CONFIRMADO")
    )

    return {
        "batch_size": len(results),
        "critical_or_confirmed": critical_count,
        "results": results,
    }


@app.get(
    "/exploit/history",
    summary="Eventos recentes no histórico da janela deslizante de correlação",
)
def exploit_history(window_seconds: int = Query(default=300, ge=60, le=3600)) -> Dict[str, Any]:
    """
    Retorna os eventos mantidos na janela deslizante de correlação temporal.
    Útil para depuração e para verificar quais eventos estão sendo
    considerados na detecção de cadeias comportamentais.
    """
    events = _get_window_events(window_seconds)
    return {
        "window_seconds": window_seconds,
        "event_count": len(events),
        "events": [
            {k: v for k, v in e.items() if k != "_stored_at"}
            for e in events
        ],
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
