"""Verify that the running SIARC API is actually persisting to PostgreSQL.

Uses only the API: no psql command is required. It compares the audit count before
and after controlled requests and captures the safe /diagnostics/database output.
"""
from __future__ import annotations
import argparse, json, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import requests


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--base-url',default='http://localhost:8080'); ap.add_argument('--api-key',default='siarc-benchmark-key'); ap.add_argument('--events',type=int,default=20); args=ap.parse_args()
    base=args.base_url.rstrip('/'); headers={'X-API-Key':args.api_key}
    before=requests.get(base+'/diagnostics/database',headers=headers,timeout=60); before.raise_for_status(); b=before.json()
    timings=[]; failures=[]; run_id=f'postgres-proof-{uuid.uuid4().hex[:8]}'
    for i in range(args.events):
        event={'timestamp':datetime.now(timezone.utc).isoformat(),'src_ip':f'10.77.0.{i+1}','dst_ip':'192.168.77.10','event_type':'port_scan','severity':'medium',
               'payload':f'synthetic proof user{i}@example.org','extra':{'experiment_run_id':run_id}}
        t=time.perf_counter()
        try:
            r=requests.post(base+'/analyze',json=event,headers=headers,timeout=30); elapsed=(time.perf_counter()-t)*1000; r.raise_for_status(); timings.append({'wall_ms':elapsed,'t_db_ms':r.json()['performance']['t_db_ms']})
        except Exception as exc: failures.append(f'{type(exc).__name__}: {exc}')
    after=requests.get(base+'/diagnostics/database',headers=headers,timeout=60); after.raise_for_status(); a=after.json()
    report={'run_id':run_id,'before':b,'after':a,'requested_events':args.events,'successful_events':len(timings),'failures':failures,
            'audit_count_delta':a.get('audit_entries',0)-b.get('audit_entries',0),'db_timings':timings,
            'postgres_confirmed':str(a.get('backend','')).startswith('postgresql') and a.get('audit_entries',0)-b.get('audit_entries',0)==len(timings)}
    out=Path('results/jisa/postgres'); out.mkdir(parents=True,exist_ok=True); (out/'postgres_verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    if not report['postgres_confirmed']:
        raise SystemExit('PostgreSQL persistence was not conclusively verified. Review the JSON report.')

if __name__=='__main__': main()
