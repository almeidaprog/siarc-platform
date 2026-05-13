"""
Log Governance — SIARC

Módulo de processamento em lote de logs.
Delega a governança LGPD ao lgpd_engine e o scoring ao risk_engine,
mantendo compatibilidade com o pipeline de arquivos .jsonl.
"""
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scripts.lgpd_engine import apply_lgpd_governance, LegalBasis
from scripts.risk_engine import calculate_risk


def process_events(lines: Iterable[str]) -> List[Dict[str, Any]]:
    """
    Processa uma sequência de linhas JSON (formato JSONL).

    Para cada evento:
      - aplica governança LGPD completa (sanitização + decisão)
      - calcula score de risco multifatorial
      - retorna evento sanitizado com metadados de governança e risco
    """
    processed: List[Dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        raw: Dict[str, Any] = json.loads(line)

        sanitized, gov = apply_lgpd_governance(
            raw,
            legal_basis=LegalBasis.SECURITY_RESEARCH,
            purpose="Processamento em lote — auditoria SIARC",
        )
        risk = calculate_risk(raw)

        result = {
            **sanitized,
            "event_id": gov.event_id,
            "governance_status": gov.compliance_status,
            "pii_count": len(gov.pii_detected),
            "risk_score": risk.score,
            "risk_level": risk.level,
            "recommended_action": risk.recommended_action,
            "xai_explanation": risk.xai_explanation,
        }
        processed.append(result)
    return processed


def main() -> None:
    input_path = Path("data/sample_logs/network_events.jsonl")
    output_path = Path("data/processed_events.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    result = process_events(input_path.read_text(encoding="utf-8").splitlines())
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Eventos processados: {len(result)}")
    print(f"Saída: {output_path}")


if __name__ == "__main__":
    main()
