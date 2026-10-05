import json
from scripts.lgpd_engine import apply_lgpd_governance


def test_masks_nested_pii_and_does_not_leak_raw_values():
    email='alice.synthetic@example.org'
    ip='10.10.20.30'
    event={'timestamp':'2026-09-01T12:00:00','payload':f'email={email}','extra':{'items':[{'origin':ip}]}}
    sanitized, decision=apply_lgpd_governance(event,event_id='pii-test')
    text=json.dumps(sanitized,ensure_ascii=False)
    assert email not in text
    assert ip not in text
    types={d.pattern_matched for d in decision.pii_detected}
    assert 'email' in types
    assert 'ip_private' in types


def test_invalid_document_numbers_are_not_classified_as_valid_cpf_cnpj():
    event={'timestamp':'2026-09-01T12:00:00','payload':'cpf=111.111.111-11 cnpj=11.111.111/1111-11'}
    _, decision=apply_lgpd_governance(event,event_id='invalid-docs')
    types=[d.pattern_matched for d in decision.pii_detected]
    assert 'cpf' not in types
    assert 'cnpj' not in types
