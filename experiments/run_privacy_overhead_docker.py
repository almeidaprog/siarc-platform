"""Repeated sanitizer OFF/ON benchmark against Docker/PostgreSQL.

The API container is recreated between modes so SIARC_SANITIZER_ENABLED is an
actual process environment change. Each mode is measured with repeated Locust
runs, preserving raw CSV files and stage metrics.
"""
from __future__ import annotations
import argparse, csv, json, os, shutil, statistics, subprocess, time, uuid
from pathlib import Path
import requests

DOCKER = ['docker'] if shutil.which('docker') else ['wsl.exe', '--', 'docker']


def wait_health(base,timeout=90):
    end=time.time()+timeout
    while time.time()<end:
        try:
            if requests.get(base.rstrip('/')+'/health',timeout=3).ok: return
        except Exception: pass
        time.sleep(2)
    raise RuntimeError('SIARC API did not become healthy.')

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--users',type=int,default=25); ap.add_argument('--repeats',type=int,default=3); ap.add_argument('--run-time',default='45s'); ap.add_argument('--host',default='http://localhost:8080'); ap.add_argument('--api-key',default='siarc-benchmark-key'); args=ap.parse_args()
    root=Path('results/jisa/privacy_overhead'); root.mkdir(parents=True,exist_ok=True); rows=[]
    for enabled in (0,1):
        env=os.environ.copy(); env['SIARC_SANITIZER_ENABLED']=str(enabled)
        subprocess.run(DOCKER+['compose','up','-d','--force-recreate','siarc-api'],env=env,check=True)
        wait_health(args.host)
        for rep in range(1,args.repeats+1):
            run_id=f"privacy-{enabled}-r{rep}-{uuid.uuid4().hex[:6]}"; prefix=root/run_id
            runenv=os.environ.copy(); runenv['SIARC_API_KEY']=args.api_key; runenv['SIARC_RUN_ID']=run_id
            subprocess.run(['locust','-f','experiments/locustfile.py','--headless','--host',args.host,'-u',str(args.users),'-r',str(min(args.users,50)),'-t',args.run_time,'--csv',str(prefix),'--only-summary'],env=runenv,check=True)
            agg={}
            with Path(str(prefix)+'_stats.csv').open(encoding='utf-8-sig') as fh:
                for r in csv.DictReader(fh):
                    if r['Name']=='Aggregated': agg=r; break
            m=requests.get(args.host.rstrip('/')+'/metrics/recent',params={'limit':5000,'run_id':run_id},headers={'X-API-Key':args.api_key},timeout=20).json().get('metrics',[])
            vals=[float(x['t_total_ms']) for x in m]; san=[float(x['t_san_ms']) for x in m]
            rows.append({'sanitizer_enabled':enabled,'repeat':rep,'run_id':run_id,'users':args.users,'requests_per_s':float(agg['Requests/s']),
                         'avg_response_ms':float(agg['Average Response Time']),'p95_response_ms':float(agg['95%']),'failures':int(float(agg['Failure Count'])),
                         'avg_internal_ms':statistics.fmean(vals) if vals else None,'avg_sanitizer_ms':statistics.fmean(san) if san else None,'stage_metric_count':len(m)})
    # Restore safe default enabled state.
    env=os.environ.copy(); env['SIARC_SANITIZER_ENABLED']='1'; subprocess.run(DOCKER+['compose','up','-d','--force-recreate','siarc-api'],env=env,check=True); wait_health(args.host)
    groups={mode:[r for r in rows if r['sanitizer_enabled']==mode] for mode in (0,1)}
    base=statistics.fmean(r['avg_internal_ms'] for r in groups[0] if r['avg_internal_ms'] is not None)
    full=statistics.fmean(r['avg_internal_ms'] for r in groups[1] if r['avg_internal_ms'] is not None)
    report={'runs':rows,'summary':{'users':args.users,'repeats_per_mode':args.repeats,'baseline_internal_ms':base,'sanitizer_internal_ms':full,'overhead_pct':((full-base)/base*100) if base else None}}
    (root/'privacy_overhead.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['summary'],indent=2))

if __name__=='__main__': main()
