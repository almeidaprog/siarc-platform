import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SEVERITY_WEIGHT = {"low": 15, "medium": 35, "high": 65, "critical": 90}
EVENT_WEIGHT = {
    "port_scan": 20,
    "suspicious_binary": 35,
    "exploit_attempt": 45,
    "credential_abuse": 40,
}


def mask_value(text: str) -> str:
    text = EMAIL_RE.sub("[EMAIL_REDACTED]", text)
    text = CPF_RE.sub("[CPF_REDACTED]", text)
    return text


def sanitize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in event.items():
        if key in {"user_email", "cpf"}:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, str):
            sanitized[key] = mask_value(value)
        else:
            sanitized[key] = value
    return sanitized


def calculate_initial_risk_score(event: Dict[str, Any]) -> int:
    severity = str(event.get("severity", "low")).lower()
    event_type = str(event.get("event_type", "unknown")).lower()
    base = SEVERITY_WEIGHT.get(severity, 10)
    event_bonus = EVENT_WEIGHT.get(event_type, 5)
    payload = str(event.get("payload", "")).lower()

    indicators = 0
    for token in ("polymorphic", "mutável", "mutavel", "exploit", "privilege", "escalation", "cve"):
        if token in payload:
            indicators += 1

    score = base + event_bonus + min(indicators * 5, 20)
    return max(0, min(score, 100))


def process_events(lines: Iterable[str]) -> list[Dict[str, Any]]:
    processed = []
    for line in lines:
        if not line.strip():
            continue
        event = json.loads(line)
        clean = sanitize_event(event)
        clean["cyber_security_score_preliminar"] = calculate_initial_risk_score(event)
        clean["governance_status"] = "LGPD_SANITIZED"
        processed.append(clean)
    return processed


def main() -> None:
    input_path = Path("data/sample_logs/network_events.jsonl")
    output_path = Path("data/processed_events.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = process_events(input_path.read_text(encoding="utf-8").splitlines())
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Eventos processados: {len(result)}")
    print(f"Saída: {output_path}")


if __name__ == "__main__":
    main()
