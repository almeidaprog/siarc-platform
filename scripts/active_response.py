"""Decisão de resposta ativa usada nos testes de julho.

As ações deste arquivo são simuladas. O projeto não altera firewall nem
remove computadores reais da rede.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


def build_active_response(
    *,
    score: int,
    risk_level: str,
    target_ip: Optional[str],
    event_id: str,
    is_zero_day: bool = False,
    verdict: Optional[str] = None,
) -> Dict[str, Any]:
    """Escolhe a ação de acordo com o score calculado."""
    level = (risk_level or "").upper()
    verdict_normalized = (verdict or "").upper()
    target = target_ip or "NAO_INFORMADO"

    critical = (
        score >= 80
        or level in {"CRÍTICO", "CRITICO"}
        or verdict_normalized == "EXPLOIT_CRITICO"
        or is_zero_day
    )

    if critical:
        action = "ISOLAR_HOST"
        status = "ISOLAMENTO_SIMULADO"
        message = f"O host {target} seria isolado da rede para análise."
    elif score >= 60:
        action = "ALERTAR_EQUIPE"
        status = "ALERTA_GERADO"
        message = "A equipe de segurança deve verificar o evento."
    elif score >= 30:
        action = "INVESTIGAR"
        status = "INVESTIGACAO_RECOMENDADA"
        message = "O evento deve ser analisado manualmente."
    else:
        action = "MONITORAR"
        status = "MONITORAMENTO"
        message = "O evento será mantido em monitoramento."

    return {
        "response_id": f"RESP-{uuid.uuid4().hex[:8].upper()}",
        "event_id": event_id,
        "status": status,
        "simulated": True,
        "action": action,
        "target_ip": target,
        "score": score,
        "risk_level": risk_level,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "requires_human_review": action != "MONITORAR",
        "message": message,
    }
