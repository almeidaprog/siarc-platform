"""Replay UNSW-NB15 rows through SIARC for stability/throughput experiments.

This adapter is intentionally not an accuracy experiment: the UNSW label is used
only to construct a representative SIARC event category/severity. The paper
therefore reports replay stability and throughput, not detection precision/recall.
"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import argparse, json, os, statistics, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

os.environ.setdefault("SIARC_API_KEY","siarc-benchmark-key")
os.environ.setdefault("DATABASE_URL","sqlite:///data/unsw_replay_audit.db")
os.environ.setdefault("SIARC_SANITIZER_ENABLED","1")

from fastapi.testclient import TestClient
from scripts.siarc_api import app

HEADERS={"X-API-Key":os.environ["SIARC_API_KEY"]}
MAP={
    "Normal": ("unknown","low"),
    "Fuzzers": ("exploit_attempt","medium"),
    "Analysis": ("port_scan","medium"),
    "Backdoor": ("command_and_control","high"),
    "Backdoors": ("command_and_control","high"),
    "DoS": ("brute_force","high"),
    "Exploits": ("exploit_attempt","high"),
    "Generic": ("unknown","medium"),
    "Reconnaissance": ("port_scan","medium"),
    "Shellcode": ("exploit_attempt","critical"),
    "Worms": ("lateral_movement","critical"),
}

def to_event(row, i):
    cat=str(row.get('attack_cat','Normal'))
    et,sev=MAP.get(cat,("unknown","medium" if int(row.get('label',0)) else "low"))
    # Training partition omits IP addresses. Documentation fields are serialized into payload.
    payload=(f"UNSW-NB15 category={cat} proto={row.get('proto')} service={row.get('service')} "
             f"state={row.get('state')} sbytes={row.get('sbytes')} dbytes={row.get('dbytes')} "
             f"rate={row.get('rate')}")
    return {"timestamp":datetime.now(timezone.utc).isoformat(),"src_ip":f"10.20.{(i//250)%250}.{(i%250)+1}",
            "dst_ip":"192.168.20.10","event_type":et,"severity":sev,"payload":payload,
            "extra":{"dataset":"UNSW-NB15","attack_cat":cat,"label":int(row.get('label',0))}}

def send(event):
    with TestClient(app) as c:
        t=time.perf_counter(); r=c.post('/analyze',json=event,headers=HEADERS); ms=(time.perf_counter()-t)*1000
        r.raise_for_status(); return ms

def pct(vals,p):
    vals=sorted(vals); k=(len(vals)-1)*p; a=int(k); b=min(a+1,len(vals)-1)
    return vals[a] if a==b else vals[a]*(b-k)+vals[b]*(k-a)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--csv',default='data/UNSW_NB15_training-set.csv'); ap.add_argument('--rows',type=int,default=1000); ap.add_argument('--concurrency',type=int,default=25); a=ap.parse_args()
    df=pd.read_csv(a.csv,nrows=a.rows)
    events=[to_event(r,i) for i,(_,r) in enumerate(df.iterrows())]
    start=time.perf_counter(); times=[]; errors=0
    with ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        fs=[ex.submit(send,e) for e in events]
        for f in as_completed(fs):
            try: times.append(f.result())
            except Exception: errors+=1
    dur=time.perf_counter()-start
    out={"dataset":"UNSW-NB15 training partition","rows":len(events),"concurrency":a.concurrency,"duration_s":round(dur,3),"throughput_eps":round((len(events)-errors)/dur,2),
         "avg_latency_ms":round(statistics.fmean(times),3),"p95_latency_ms":round(pct(times,.95),3),"errors":errors,"error_rate_pct":round(errors/len(events)*100,3),
         "evaluation_scope":"replay stability/throughput only; not detection accuracy"}
    Path('results').mkdir(exist_ok=True); Path('results/unsw_replay.json').write_text(json.dumps(out,indent=2),encoding='utf-8'); print(out)
if __name__=='__main__': main()
