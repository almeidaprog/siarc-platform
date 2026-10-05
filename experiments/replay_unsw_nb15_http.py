"""Replay UNSW-NB15 through the running Docker SIARC API and classify failures.

Unlike the old portable TestClient replay, this script sends real HTTP requests to
FastAPI/PostgreSQL. Every failed request is written to CSV with row index,
HTTP status or exception class, allowing the previously observed errors to be
investigated rather than reported only as a count.
"""
from __future__ import annotations
import argparse, csv, json, statistics, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
import requests

MAP={
    'Normal':('unknown','low'),'Fuzzers':('exploit_attempt','medium'),'Analysis':('port_scan','medium'),
    'Backdoor':('command_and_control','high'),'Backdoors':('command_and_control','high'),
    'DoS':('brute_force','high'),'Exploits':('exploit_attempt','high'),'Generic':('unknown','medium'),
    'Reconnaissance':('port_scan','medium'),'Shellcode':('exploit_attempt','critical'),'Worms':('lateral_movement','critical'),
}
_thread=threading.local()

def session():
    if not hasattr(_thread,'s'):
        _thread.s=requests.Session()
    return _thread.s

def to_event(row,i,run_id):
    cat=str(row.get('attack_cat','Normal')); et,sev=MAP.get(cat,('unknown','medium' if int(row.get('label',0)) else 'low'))
    payload=(f"UNSW-NB15 category={cat} proto={row.get('proto')} service={row.get('service')} state={row.get('state')} "
             f"sbytes={row.get('sbytes')} dbytes={row.get('dbytes')} rate={row.get('rate')}")
    return {'timestamp':datetime.now(timezone.utc).isoformat(),'src_ip':f'10.20.{(i//250)%250}.{(i%250)+1}',
            'dst_ip':'192.168.20.10','event_type':et,'severity':sev,'payload':payload,
            'extra':{'dataset':'UNSW-NB15','attack_cat':cat,'label':int(row.get('label',0)),'experiment_run_id':run_id}}

def pct(vals,p):
    if not vals: return None
    vals=sorted(vals); k=(len(vals)-1)*p; a=int(k); b=min(a+1,len(vals)-1)
    return vals[a] if a==b else vals[a]*(b-k)+vals[b]*(k-a)

def send(url,headers,event,row_index,timeout):
    t=time.perf_counter()
    try:
        r=session().post(url,json=event,headers=headers,timeout=timeout)
        ms=(time.perf_counter()-t)*1000
        if r.status_code>=400:
            return None, {'row_index':row_index,'kind':'http','status':r.status_code,'error':r.text[:500]}
        return ms, None
    except Exception as exc:
        return None, {'row_index':row_index,'kind':'exception','status':'','error':f'{type(exc).__name__}: {exc}'[:500]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--csv',default='data/UNSW_NB15_training-set.csv')
    ap.add_argument('--rows',type=int,default=1500)
    ap.add_argument('--concurrency',type=int,default=20)
    ap.add_argument('--base-url',default='http://localhost:8080')
    ap.add_argument('--api-key',default='siarc-benchmark-key')
    ap.add_argument('--timeout',type=float,default=30.0)
    args=ap.parse_args()
    run_id=f"unsw-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    df=pd.read_csv(args.csv,nrows=args.rows)
    events=[to_event(r,i,run_id) for i,(_,r) in enumerate(df.iterrows())]
    headers={'X-API-Key':args.api_key}; url=args.base_url.rstrip('/')+'/analyze'
    start=time.perf_counter(); times=[]; errors=[]
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        fs=[ex.submit(send,url,headers,e,i,args.timeout) for i,e in enumerate(events)]
        for f in as_completed(fs):
            ms,err=f.result()
            if err: errors.append(err)
            else: times.append(ms)
    dur=time.perf_counter()-start
    outdir=Path('results/jisa/unsw_replay'); outdir.mkdir(parents=True,exist_ok=True)
    report={
        'run_id':run_id,'dataset':'UNSW-NB15','rows':len(events),'concurrency':args.concurrency,
        'duration_s':round(dur,3),'successful_requests':len(times),'errors':len(errors),
        'error_rate_pct':round(len(errors)/len(events)*100,4) if events else 0.0,
        'throughput_eps':round(len(times)/dur,3) if dur else 0.0,
        'avg_latency_ms':round(statistics.fmean(times),3) if times else None,
        'median_latency_ms':round(statistics.median(times),3) if times else None,
        'p95_latency_ms':round(pct(times,.95),3) if times else None,
        'p99_latency_ms':round(pct(times,.99),3) if times else None,
        'max_latency_ms':round(max(times),3) if times else None,
        'base_url':args.base_url,'scope':'Docker HTTP replay / stability; not predictive accuracy.'
    }
    (outdir/'unsw_http_replay.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    with (outdir/'unsw_http_errors.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=['row_index','kind','status','error']); w.writeheader(); w.writerows(sorted(errors,key=lambda x:x['row_index']))
    print(json.dumps(report,ensure_ascii=False,indent=2))
    print(f"Error details: {outdir/'unsw_http_errors.csv'}")

if __name__=='__main__': main()
