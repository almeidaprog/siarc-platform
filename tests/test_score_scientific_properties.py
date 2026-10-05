from scripts.risk_engine import calculate_risk


def test_risk_is_monotonic_when_threat_evidence_is_added():
    base={'timestamp':'2026-09-01T12:00:00','src_ip':'10.0.0.5','event_type':'unknown','severity':'low','payload':''}
    sequence=[
        base,
        {**base,'severity':'medium'},
        {**base,'severity':'medium','event_type':'port_scan'},
        {**base,'severity':'high','event_type':'exploit_attempt','payload':'exploit shellcode'},
        {**base,'severity':'critical','event_type':'exploit_attempt','payload':'zero-day CVE shellcode privilege escalation'},
    ]
    scores=[calculate_risk(x).score for x in sequence]
    assert scores == sorted(scores)


def test_score_is_bounded_and_level_matches_thresholds():
    cases=[
        ({'severity':'low','event_type':'unknown','src_ip':'127.0.0.1','payload':''},'BAIXO'),
        ({'severity':'medium','event_type':'unknown','src_ip':'127.0.0.1','payload':''},'MÉDIO'),
        ({'severity':'medium','event_type':'port_scan','src_ip':'10.0.0.2','payload':''},'ALTO'),
        ({'severity':'critical','event_type':'exploit_attempt','src_ip':'203.0.113.88','payload':'CVE shellcode zero-day'},'CRÍTICO'),
    ]
    for event,expected in cases:
        risk=calculate_risk(event)
        assert 0 <= risk.score <= 100
        assert risk.level == expected
