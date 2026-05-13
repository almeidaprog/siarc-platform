"""
LGPD Governance Engine — SIARC Sprint Maio/2026

Implementa a camada completa de governança de dados conforme Lei nº 13.709/2018.
Cobre: detecção de PII, categorização por sensibilidade, estratégias de mascaramento,
base legal de tratamento e avaliação dos 10 princípios do Art. 6.
"""
import re
import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Enumerações LGPD
# ---------------------------------------------------------------------------

class DataCategory(str, Enum):
    """Categorias de dados conforme LGPD Art. 5."""
    PERSONAL = "DADO_PESSOAL"
    SENSITIVE = "DADO_PESSOAL_SENSIVEL"   # Art. 5, II
    ANONYMOUS = "DADO_ANONIMIZADO"
    NON_PERSONAL = "NAO_PESSOAL"


class MaskingStrategy(str, Enum):
    """Estratégias de mascaramento aplicadas conforme categoria e risco."""
    FULL_REDACTION = "REDACAO_TOTAL"
    PARTIAL = "MASCARAMENTO_PARCIAL"
    PSEUDONYMIZATION = "PSEUDONIMIZACAO"
    TOKENIZATION = "TOKENIZACAO"


class LegalBasis(str, Enum):
    """Bases legais de tratamento — LGPD Art. 7 (dados pessoais) e Art. 11 (sensíveis)."""
    CONSENT = "CONSENTIMENTO"
    LEGAL_OBLIGATION = "OBRIGACAO_LEGAL"
    CONTRACT = "EXECUCAO_DE_CONTRATO"
    LEGITIMATE_INTEREST = "INTERESSE_LEGITIMO"
    VITAL_INTEREST = "PROTECAO_DA_VIDA"
    PUBLIC_INTEREST = "INTERESSE_PUBLICO"
    SECURITY_RESEARCH = "PESQUISA_DE_SEGURANCA"


# ---------------------------------------------------------------------------
# Estruturas de dados
# ---------------------------------------------------------------------------

@dataclass
class PIIDetection:
    """Registro de um dado pessoal detectado e mascarado."""
    field_name: str
    original_value: str
    masked_value: str
    category: DataCategory
    strategy: MaskingStrategy
    pattern_matched: str
    lgpd_article: str


@dataclass
class GovernanceDecision:
    """Decisão de governança tomada sobre um evento."""
    event_id: str
    timestamp: str
    legal_basis: LegalBasis
    purpose: str
    pii_detected: List[PIIDetection]
    data_minimization_applied: bool
    retention_days: int
    compliance_status: str
    principles_evaluated: Dict[str, bool]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "legal_basis": self.legal_basis.value,
            "purpose": self.purpose,
            "pii_count": len(self.pii_detected),
            "pii_fields": [
                {
                    "field": d.field_name,
                    "category": d.category.value,
                    "strategy": d.strategy.value,
                    "lgpd_article": d.lgpd_article,
                }
                for d in self.pii_detected
            ],
            "data_minimization_applied": self.data_minimization_applied,
            "retention_days": self.retention_days,
            "compliance_status": self.compliance_status,
            "principles_evaluated": self.principles_evaluated,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Padrões de detecção de PII
# (padrão, categoria, estratégia, artigo LGPD de referência)
# ---------------------------------------------------------------------------

_PATTERNS: Dict[str, Tuple[re.Pattern, DataCategory, MaskingStrategy, str]] = {
    "email": (
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        DataCategory.PERSONAL,
        MaskingStrategy.PSEUDONYMIZATION,
        "Art. 5, I",
    ),
    "cpf": (
        re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        DataCategory.PERSONAL,
        MaskingStrategy.FULL_REDACTION,
        "Art. 5, I",
    ),
    "cnpj": (
        re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        DataCategory.PERSONAL,
        MaskingStrategy.PARTIAL,
        "Art. 5, I",
    ),
    "phone_br": (
        re.compile(
            r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[-\s]?\d{4}\b"
        ),
        DataCategory.PERSONAL,
        MaskingStrategy.PARTIAL,
        "Art. 5, I",
    ),
    "rg": (
        re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9xX]\b"),
        DataCategory.PERSONAL,
        MaskingStrategy.FULL_REDACTION,
        "Art. 5, I",
    ),
    # IPs privados podem identificar usuários em redes internas
    "ip_private": (
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        DataCategory.PERSONAL,
        MaskingStrategy.PSEUDONYMIZATION,
        "Art. 5, I — identificação indireta em rede interna",
    ),
}

# Nomes de campos que, por si só, indicam dado sensível
_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset({
    "cpf", "user_email", "email", "nome", "name", "telefone", "phone",
    "rg", "passaporte", "passport", "endereco", "address",
    "password", "senha", "token", "api_key", "secret", "credential",
    "usuario", "username", "login",
})

# 10 princípios LGPD Art. 6
_LGPD_PRINCIPLES: List[str] = [
    "finalidade",
    "adequacao",
    "necessidade",
    "livre_acesso",
    "qualidade_dos_dados",
    "transparencia",
    "seguranca",
    "prevencao",
    "nao_discriminacao",
    "responsabilizacao",
]


# ---------------------------------------------------------------------------
# Funções de mascaramento
# ---------------------------------------------------------------------------

def _pseudonymize(value: str, prefix: str = "") -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    tag = f"{prefix}_" if prefix else ""
    return f"[PSE_{tag}{digest}]"


def _partial_mask(value: str) -> str:
    if len(value) <= 4:
        return "[MASKED]"
    visible = max(2, len(value) // 5)
    return value[:visible] + ("*" * (len(value) - visible * 2)) + value[-visible:]


def _apply_strategy(value: str, strategy: MaskingStrategy, pattern_name: str) -> str:
    if strategy == MaskingStrategy.FULL_REDACTION:
        return f"[{pattern_name.upper()}_REDACTED]"
    if strategy == MaskingStrategy.PSEUDONYMIZATION:
        return _pseudonymize(value, pattern_name.upper()[:4])
    if strategy == MaskingStrategy.PARTIAL:
        return _partial_mask(value)
    return "[REDACTED]"


# ---------------------------------------------------------------------------
# Detecção e mascaramento em texto livre
# ---------------------------------------------------------------------------

def detect_and_mask_text(
    text: str, field_name: str = ""
) -> Tuple[str, List[PIIDetection]]:
    """Varre um texto livre, detecta PII por regex e aplica mascaramento."""
    detections: List[PIIDetection] = []
    result = text

    for pattern_name, (pattern, category, strategy, article) in _PATTERNS.items():
        for match in set(pattern.findall(result)):
            masked = _apply_strategy(match, strategy, pattern_name)
            detections.append(
                PIIDetection(
                    field_name=field_name,
                    original_value=match,
                    masked_value=masked,
                    category=category,
                    strategy=strategy,
                    pattern_matched=pattern_name,
                    lgpd_article=article,
                )
            )
            result = result.replace(match, masked)

    return result, detections


# ---------------------------------------------------------------------------
# Sanitização de campos individuais (recursiva para dicts)
# ---------------------------------------------------------------------------

def sanitize_field(key: str, value: Any) -> Tuple[Any, List[PIIDetection]]:
    """Sanitiza um campo individual, incluindo dicts aninhados."""
    detections: List[PIIDetection] = []

    if key.lower() in _SENSITIVE_FIELD_NAMES and isinstance(value, str) and value:
        masked = _pseudonymize(value, "FIELD")
        detections.append(
            PIIDetection(
                field_name=key,
                original_value=value,
                masked_value=masked,
                category=DataCategory.PERSONAL,
                strategy=MaskingStrategy.PSEUDONYMIZATION,
                pattern_matched="nome_de_campo_sensivel",
                lgpd_article="Art. 5, I",
            )
        )
        return masked, detections

    if isinstance(value, str):
        masked_text, text_detections = detect_and_mask_text(value, key)
        return masked_text, text_detections

    if isinstance(value, dict):
        masked_dict: Dict[str, Any] = {}
        for k, v in value.items():
            masked_dict[k], sub_detections = sanitize_field(k, v)
            detections.extend(sub_detections)
        return masked_dict, detections

    if isinstance(value, list):
        masked_list = []
        for item in value:
            if isinstance(item, str):
                masked_item, item_detections = detect_and_mask_text(item)
                detections.extend(item_detections)
                masked_list.append(masked_item)
            else:
                masked_list.append(item)
        return masked_list, detections

    return value, detections


# ---------------------------------------------------------------------------
# Avaliação dos princípios LGPD (Art. 6)
# ---------------------------------------------------------------------------

def _evaluate_principles(
    event: Dict[str, Any],
    detections: List[PIIDetection],
    purpose: str,
) -> Dict[str, bool]:
    """Avalia cada um dos 10 princípios do Art. 6 para o evento."""
    essential_fields = {
        "timestamp", "src_ip", "dst_ip", "event_type", "severity", "payload", "extra"
    }
    non_essential = set(event.keys()) - essential_fields

    return {
        "finalidade": bool(purpose),
        "adequacao": bool(purpose and "segurança" in purpose.lower()),
        "necessidade": len(non_essential) == 0,
        "livre_acesso": True,   # API de auditoria disponível (GET /audit/entries)
        "qualidade_dos_dados": bool(event.get("timestamp")),
        "transparencia": True,  # governança_status exposto no response
        "seguranca": len(detections) > 0 or not any(
            k.lower() in _SENSITIVE_FIELD_NAMES for k in event.keys()
        ),
        "prevencao": True,      # mascaramento aplicado antes do armazenamento
        "nao_discriminacao": True,
        "responsabilizacao": True,  # trilha de auditoria ativa
    }


# ---------------------------------------------------------------------------
# Ponto de entrada principal
# ---------------------------------------------------------------------------

def apply_lgpd_governance(
    event: Dict[str, Any],
    event_id: Optional[str] = None,
    legal_basis: LegalBasis = LegalBasis.SECURITY_RESEARCH,
    purpose: str = "Auditoria de segurança cibernética — SIARC",
) -> Tuple[Dict[str, Any], GovernanceDecision]:
    """
    Aplica governança LGPD completa sobre um evento de segurança.

    Retorna:
        sanitized_event  — evento com todos os dados pessoais mascarados
        governance_decision — decisão documentada conforme Art. 37
    """
    if not event_id:
        event_id = str(uuid.uuid4())

    all_detections: List[PIIDetection] = []
    sanitized: Dict[str, Any] = {}

    for key, value in event.items():
        masked_value, detections = sanitize_field(key, value)
        sanitized[key] = masked_value
        all_detections.extend(detections)

    principles = _evaluate_principles(event, all_detections, purpose)

    notes: List[str] = []
    if all_detections:
        types = {d.pattern_matched for d in all_detections}
        notes.append(
            f"{len(all_detections)} ocorrência(s) de PII mascarada(s): {', '.join(sorted(types))}."
        )
    if not principles["necessidade"]:
        notes.append(
            "Campos não essenciais detectados — revisar coleta (princípio da necessidade, Art. 6, III)."
        )
    if not all_detections and any(
        k.lower() in _SENSITIVE_FIELD_NAMES for k in event.keys()
    ):
        notes.append("Campos com nomes sensíveis sem valor textual detectável.")

    # Avalia conformidade geral: verde se todos os princípios aprovados
    all_compliant = all(principles.values())
    compliance_status = "CONFORME_LGPD" if all_compliant else "ATENCAO_LGPD"

    decision = GovernanceDecision(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        legal_basis=legal_basis,
        purpose=purpose,
        pii_detected=all_detections,
        data_minimization_applied=len(all_detections) > 0,
        retention_days=90,
        compliance_status=compliance_status,
        principles_evaluated=principles,
        notes=notes,
    )

    return sanitized, decision
