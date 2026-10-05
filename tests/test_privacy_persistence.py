import json, os, tempfile
from pathlib import Path


def test_audit_does_not_persist_raw_source_ip():
    db=Path(tempfile.gettempdir())/'siarc_privacy_persistence_test.db'
    try: db.unlink()
    except FileNotFoundError: pass
    os.environ['DATABASE_URL']=f'sqlite:///{db}'
    os.environ['SIARC_API_KEY']='test-key'
    os.environ['SIARC_SANITIZER_ENABLED']='1'

    from fastapi.testclient import TestClient
    from scripts.siarc_api import app
    from scripts import audit_trail

    raw_ip='10.44.55.66'
    event={'timestamp':'2026-09-01T12:00:00','src_ip':raw_ip,'dst_ip':'192.168.1.1','event_type':'port_scan','severity':'medium','payload':'user synthetic@example.org'}
    with TestClient(app) as client:
        r=client.post('/analyze',json=event,headers={'X-API-Key':'test-key'})
        assert r.status_code == 200
        body=r.json()
        eid=body['event_id']
        assert raw_ip not in json.dumps(body, ensure_ascii=False)
        assert '[PSE_' in body['active_response']['target_ip']
    entries=audit_trail.get_by_event(eid)
    assert entries
    persisted=json.dumps(entries,ensure_ascii=False)
    assert raw_ip not in persisted
    assert '[PSE_' in persisted
