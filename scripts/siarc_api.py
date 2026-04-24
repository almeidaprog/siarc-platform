from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict
from scripts.log_governance import sanitize_event, calculate_initial_risk_score

app = FastAPI(title="SIARC Sandbox API", version="0.1.0")

class SecurityEvent(BaseModel):
    timestamp: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str = "unknown"
    severity: str = "low"
    payload: str = ""
    extra: Dict[str, Any] | None = None

@app.get("/health")
def health():
    return {"status": "ok", "service": "siarc-api-sandbox"}

@app.post("/analyze")
def analyze(event: SecurityEvent):
    raw = event.model_dump()
    clean = sanitize_event(raw)
    clean["cyber_security_score_preliminar"] = calculate_initial_risk_score(raw)
    clean["governance_status"] = "LGPD_SANITIZED"
    clean["xai_explanation_stub"] = [
        "peso_por_severidade",
        "peso_por_tipo_de_evento",
        "indicadores_textuais_de_exploit_ou_malware_mutavel"
    ]
    return clean
