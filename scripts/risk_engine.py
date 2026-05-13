"""
Risk Engine — SIARC Sprint Maio/2026

Motor de risco multifatorial com explicações XAI (Explainable AI).
Cada fator contribui de forma transparente para o score final,
permitindo que analistas de segurança compreendam o raciocínio.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Estruturas de dados
# ---------------------------------------------------------------------------

@dataclass
class RiskFactor:
    """Contribuição individual de um fator para o score de risco."""
    name: str
    contribution: float       # pontos adicionados ao score
    explanation: str          # justificativa em linguagem natural


@dataclass
class RiskAssessment:
    """Avaliação completa de risco com explicações XAI."""
    score: int                # 0–100
    level: str                # BAIXO | MÉDIO | ALTO | CRÍTICO
    factors: List[RiskFactor]
    xai_explanation: List[str]
    recommended_action: str
    confidence: float         # 0.0–1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "factors": [
                {"name": f.name, "contribution": f.contribution, "explanation": f.explanation}
                for f in self.factors
            ],
            "xai_explanation": self.xai_explanation,
            "recommended_action": self.recommended_action,
            "confidence": round(self.confidence, 2),
        }


# ---------------------------------------------------------------------------
# Tabelas de peso
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT: Dict[str, float] = {
    "low": 15.0,
    "medium": 35.0,
    "high": 65.0,
    "critical": 90.0,
}

_EVENT_TYPE_WEIGHT: Dict[str, float] = {
    "port_scan": 20.0,
    "suspicious_binary": 35.0,
    "exploit_attempt": 45.0,
    "credential_abuse": 40.0,
    "ransomware_behavior": 55.0,
    "data_exfiltration": 50.0,
    "lateral_movement": 42.0,
    "privilege_escalation": 48.0,
    "command_and_control": 52.0,
    "brute_force": 38.0,
    "sql_injection": 44.0,
    "xss_attempt": 30.0,
    "unknown": 5.0,
}

# Indicadores textuais no payload e seus pesos individuais
_THREAT_INDICATORS: Dict[str, float] = {
    "polymorphic": 8.0,
    "mutável": 8.0,
    "mutavel": 8.0,
    "exploit": 10.0,
    "privilege": 7.0,
    "escalation": 7.0,
    "cve": 10.0,
    "zero-day": 15.0,
    "zeroday": 15.0,
    "0day": 15.0,
    "ransomware": 12.0,
    "exfiltration": 10.0,
    "lateral": 8.0,
    "persistence": 6.0,
    "obfuscation": 9.0,
    "shellcode": 12.0,
    "rootkit": 14.0,
    "backdoor": 12.0,
    "keylogger": 10.0,
    "botnet": 10.0,
    "c2": 11.0,
    "command and control": 11.0,
    "mimikatz": 15.0,
    "cobalt strike": 15.0,
    "metasploit": 12.0,
    "powershell": 5.0,
    "base64": 4.0,
    "encoded payload": 8.0,
}

# Peso por origem do IP
_IP_CLASS_WEIGHT: Dict[str, float] = {
    "external": 15.0,
    "internal": 5.0,
    "loopback": 0.0,
    "unknown": 8.0,
}

# Ações recomendadas por faixa de score
_RECOMMENDED_ACTIONS: List[tuple] = [
    (0,  29,  "MONITORAR — Registrar evento para correlação futura. Sem ação imediata."),
    (30, 59,  "INVESTIGAR — Analisar contexto e correlacionar com outros eventos recentes."),
    (60, 79,  "ALERTAR — Notificar equipe de segurança e iniciar investigação ativa."),
    (80, 100, "RESPONDER — Isolar ativo afetado e iniciar plano de resposta a incidente."),
]


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def _classify_ip(ip: Optional[str]) -> str:
    if not ip:
        return "unknown"
    if ip in ("127.0.0.1", "::1", "localhost"):
        return "loopback"
    parts = ip.split(".")
    if len(parts) != 4:
        return "unknown"
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return "unknown"
    if a == 10:
        return "internal"
    if a == 172 and 16 <= b <= 31:
        return "internal"
    if a == 192 and b == 168:
        return "internal"
    return "external"


def _get_recommended_action(score: int) -> str:
    for low, high, action in _RECOMMENDED_ACTIONS:
        if low <= score <= high:
            return action
    return _RECOMMENDED_ACTIONS[-1][2]


def _score_to_level(score: int) -> str:
    if score < 30:
        return "BAIXO"
    if score < 60:
        return "MÉDIO"
    if score < 80:
        return "ALTO"
    return "CRÍTICO"


# ---------------------------------------------------------------------------
# Cálculo do risco
# ---------------------------------------------------------------------------

def calculate_risk(event: Dict[str, Any]) -> RiskAssessment:
    """
    Calcula o risco multifatorial de um evento de segurança.

    Fatores avaliados:
      1. Severidade declarada
      2. Tipo de evento
      3. Indicadores de ameaça no payload
      4. Classificação do IP de origem
      5. Anomalia temporal (horário fora do expediente)
    """
    factors: List[RiskFactor] = []

    # ── Fator 1: Severidade ──────────────────────────────────────────────
    severity = str(event.get("severity", "low")).lower()
    sev_pts = _SEVERITY_WEIGHT.get(severity, 10.0)
    factors.append(RiskFactor(
        name="severidade",
        contribution=sev_pts,
        explanation=f"Severidade '{severity}' → {sev_pts:.0f} pts (escala: low=15, medium=35, high=65, critical=90)",
    ))

    # ── Fator 2: Tipo de evento ──────────────────────────────────────────
    event_type = str(event.get("event_type", "unknown")).lower()
    evt_pts = _EVENT_TYPE_WEIGHT.get(event_type, 5.0)
    factors.append(RiskFactor(
        name="tipo_de_evento",
        contribution=evt_pts,
        explanation=f"Tipo '{event_type}' → {evt_pts:.0f} pts adicionais",
    ))

    # ── Fator 3: Indicadores textuais no payload ─────────────────────────
    payload = str(event.get("payload", "")).lower()
    matched: Dict[str, float] = {}
    for indicator, pts in _THREAT_INDICATORS.items():
        if indicator in payload:
            matched[indicator] = pts

    indicator_pts = min(sum(matched.values()), 25.0)   # cap em 25
    if matched:
        factors.append(RiskFactor(
            name="indicadores_de_ameaca",
            contribution=indicator_pts,
            explanation=(
                f"Indicadores detectados no payload: {', '.join(sorted(matched.keys()))} "
                f"→ {indicator_pts:.0f} pts (máx. 25)"
            ),
        ))

    # ── Fator 4: Classificação do IP de origem ───────────────────────────
    src_ip = event.get("src_ip")
    ip_class = _classify_ip(src_ip)
    ip_pts = _IP_CLASS_WEIGHT.get(ip_class, 8.0)
    factors.append(RiskFactor(
        name="origem_ip",
        contribution=ip_pts,
        explanation=f"IP {src_ip or 'desconhecido'} classificado como '{ip_class}' → {ip_pts:.0f} pts",
    ))

    # ── Fator 5: Anomalia temporal ───────────────────────────────────────
    ts = event.get("timestamp", "")
    time_pts = 0.0
    time_note = ""
    try:
        dt = datetime.fromisoformat(str(ts))
        hour = dt.hour
        if hour < 6 or hour > 22:
            time_pts = 8.0
            time_note = f"Evento às {hour:02d}h (fora do expediente) → {time_pts:.0f} pts"
        else:
            time_note = f"Evento às {hour:02d}h (horário normal) → 0 pts"
    except (ValueError, TypeError):
        time_note = "Timestamp inválido ou ausente → 0 pts"

    if time_pts > 0:
        factors.append(RiskFactor(
            name="anomalia_temporal",
            contribution=time_pts,
            explanation=time_note,
        ))

    # ── Score final ───────────────────────────────────────────────────────
    total = sum(f.contribution for f in factors)
    score = max(0, min(int(round(total)), 100))
    level = _score_to_level(score)

    xai_lines = [f"[{f.name}] {f.explanation}" for f in factors]
    xai_lines.append(
        f"Score final: {score}/100 — Nível: {level} "
        f"(soma dos fatores: {total:.1f}, truncado em 100)"
    )

    # Confiança aumenta com número de fatores avaliados
    confidence = min(1.0, 0.4 + len(factors) * 0.12)

    return RiskAssessment(
        score=score,
        level=level,
        factors=factors,
        xai_explanation=xai_lines,
        recommended_action=_get_recommended_action(score),
        confidence=confidence,
    )
