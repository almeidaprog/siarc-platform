"""Portable SIARC quantitative benchmark.

Uses FastAPI TestClient and SQLite for reproducible local verification. The Docker
experiment uses the same endpoint with PostgreSQL and Locust. Results are saved
as CSV/JSON; no numbers are hard-coded in the article-generation pipeline.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("SIARC_API_KEY", "siarc-benchmark-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///data/benchmark_audit.db")

from fastapi.testclient import TestClient
from scripts.siarc_api import app

HEADERS={"X-API-Key": os.environ["SIARC_API_KEY"]}


def payload(i: int):
    critical = i % 5 == 0
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": f"203.0.113.{(i%250)+1}" if critical else f"10.0.{(i//250)%250}.{(i%250)+1}",
        "dst_ip": "192.168.10.20",
        "event_type": "exploit_attempt" if critical else random.choice(["port_scan","brute_force","unknown"]),
        "severity": "critical" if critical else random.choice(["low","medium","high"]),
        "payload": "usuario.teste@empresa.com.br CPF 123.456.789-09 CVE-2024-0001 shellcode" if critical else "usuario.teste@empresa.com.br source=10.0.0.44",
        "extra": {"sample": i},
    }


def one(i: int):
    with TestClient(app) as client:
        t=time.perf_counter()
        r=client.post('/analyze', json=payload(i), headers=HEADERS)
        wall=(time.perf_counter()-t)*1000
        r.raise_for_status()
        d=r.json()
        return wall, d['performance']


def percentile(vals, p):
    vals=sorted(vals)
    if not vals: return 0.0
    k=(len(vals)-1)*p
    f=int(k); c=min(f+1,len(vals)-1)
    return vals[f] if f==c else vals[f]*(c-k)+vals[c]*(k-f)


def run(concurrency: int, events: int):
    start=time.perf_counter(); rows=[]; errors=0
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures=[ex.submit(one,i) for i in range(events)]
        for f in as_completed(futures):
            try: rows.append(f.result())
            except Exception as e: errors += 1
    dur=time.perf_counter()-start
    walls=[x[0] for x in rows]
    stages=[x[1] for x in rows]
    avg=lambda key: statistics.fmean([x[key] for x in stages]) if stages else 0.0
    return {
        "concurrent_users": concurrency,
        "events": events,
        "duration_s": round(dur,4),
        "throughput_eps": round(len(rows)/dur,2) if dur else 0.0,
        "avg_latency_ms": round(statistics.fmean(walls),3) if walls else 0.0,
        "p95_latency_ms": round(percentile(walls,.95),3),
        "avg_t_san_ms": round(avg('t_san_ms'),4),
        "avg_t_score_ms": round(avg('t_score_ms'),4),
        "avg_t_db_ms": round(avg('t_db_ms'),4),
        "avg_t_total_ms": round(avg('t_total_ms'),4),
        "error_rate_pct": round(errors/events*100,3),
        "backend": "SQLite local verification",
    }


def privacy_overhead(events=500):
    out=[]
    for enabled in (False, True):
        os.environ['SIARC_SANITIZER_ENABLED']='1' if enabled else '0'
        result=run(10,events)
        result['sanitizer_enabled']=enabled
        out.append(result)
    base=out[0]['avg_t_total_ms']; full=out[1]['avg_t_total_ms']
    overhead=((full-base)/base*100) if base else 0.0
    return out, round(overhead,2)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--events',type=int,default=300); args=ap.parse_args()
    Path('results').mkdir(exist_ok=True)
    os.environ['SIARC_SANITIZER_ENABLED']='1'
    loads=[]
    for c in [1,10,25,50]:
        loads.append(run(c,args.events))
        print(loads[-1])
    po, overhead=privacy_overhead(max(200,args.events))
    bundle={"generated_at":datetime.now(timezone.utc).isoformat(),"load":loads,"privacy":po,"privacy_overhead_pct":overhead,
            "note":"Portable local verification uses SQLite because PostgreSQL is exercised by the Docker/Locust deployment."}
    Path('results/local_benchmark.json').write_text(json.dumps(bundle,indent=2),encoding='utf-8')
    with open('results/local_load.csv','w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=loads[0].keys()); w.writeheader(); w.writerows(loads)
    print('privacy_overhead_pct',overhead)

if __name__=='__main__': main()
