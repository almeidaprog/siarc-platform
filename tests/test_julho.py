from scripts.active_response import build_active_response
from scripts.risk_engine import calculate_risk


def test_score_ranges_and_actions():
    cases = [
        ({"severity": "low", "event_type": "unknown", "src_ip": "127.0.0.1", "payload": ""}, "BAIXO", "MONITORAR"),
        ({"severity": "medium", "event_type": "unknown", "src_ip": "127.0.0.1", "payload": ""}, "MÉDIO", "INVESTIGAR"),
        ({"severity": "medium", "event_type": "port_scan", "src_ip": "10.0.0.2", "payload": ""}, "ALTO", "ALERTAR_EQUIPE"),
        ({"severity": "critical", "event_type": "exploit_attempt", "src_ip": "203.0.113.88", "payload": "CVE shellcode zero-day"}, "CRÍTICO", "ISOLAR_HOST"),
    ]

    for index, (event, expected_level, expected_action) in enumerate(cases):
        risk = calculate_risk(event)
        response = build_active_response(
            score=risk.score,
            risk_level=risk.level,
            target_ip=event["src_ip"],
            event_id=f"test-{index}",
        )
        assert risk.level == expected_level
        assert response["action"] == expected_action


if __name__ == "__main__":
    test_score_ranges_and_actions()
    print("Testes de julho concluídos.")
