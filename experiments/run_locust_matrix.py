"""Run the repeated Locust matrix requested for the SIARC/JISA revision.

Default full matrix: 1, 5, 10, 25, 50, 100, 150, 200 users, three repetitions.
Each run has a unique run_id propagated into SIARC stage metrics. CSV exports,
metadata, and stage summaries are retained for statistical analysis.
"""
from __future__ import annotations
import argparse, csv, json, os, random, shutil, statistics, subprocess, sys, time, uuid
from pathlib import Path
import requests


def mean(xs): return statistics.fmean(xs) if xs else None

def percentile(xs,p):
    if not xs: return None
    xs=sorted(xs); k=(len(xs)-1)*p; a=int(k); b=min(a+1,len(xs)-1)
    return xs[a] if a==b else xs[a]*(b-k)+xs[b]*(k-a)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--users',default='1,5,10,25,50,100,150,200')
    ap.add_argument('--repeats',type=int,default=3)
    ap.add_argument('--run-time',default='45s')
    ap.add_argument('--spawn-rate',type=float,default=50.0)
    ap.add_argument('--host',default='http://localhost:8080')
    ap.add_argument('--api-key',default='siarc-benchmark-key')
    ap.add_argument('--warmup-time',default='15s')
    ap.add_argument('--cooldown-seconds',type=int,default=5)
    ap.add_argument('--seed',type=int,default=20260901)
    args=ap.parse_args()
    if not shutil.which('locust'):
        raise SystemExit('Locust not found. Run: pip install -r requirements.txt')
    levels=[int(x) for x in args.users.split(',') if x.strip()]
    root=Path('results/jisa/locust_matrix'); root.mkdir(parents=True,exist_ok=True)
    summary=[]
    # Warm-up is intentionally excluded from analysis.
    warm_id=f"warmup-{uuid.uuid4().hex[:6]}"
    warm_env=os.environ.copy(); warm_env['SIARC_API_KEY']=args.api_key; warm_env['SIARC_RUN_ID']=warm_id
    subprocess.run(['locust','-f','experiments/locustfile.py','--headless','--host',args.host,'-u','10','-r','10','-t',args.warmup_time,'--only-summary'],env=warm_env,check=True)
    time.sleep(args.cooldown_seconds)

    for rep in range(1,args.repeats+1):
        ordered=list(levels)
        random.Random(args.seed + rep).shuffle(ordered)
        for users in ordered:
            run_id=f"u{users}-r{rep}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
            prefix=root/run_id
            env=os.environ.copy(); env['SIARC_API_KEY']=args.api_key; env['SIARC_RUN_ID']=run_id
            cmd=['locust','-f','experiments/locustfile.py','--headless','--host',args.host,
                 '-u',str(users),'-r',str(min(args.spawn_rate,max(users,1))),'-t',args.run_time,
                 '--csv',str(prefix),'--csv-full-history','--only-summary']
            print('\nRUN',run_id,' '.join(cmd),flush=True)
            started=time.time()
            proc=subprocess.run(cmd,env=env)
            ended=time.time()
            # Pull stage metrics produced only by this run_id.
            metrics=[]; metric_error=None
            try:
                r=requests.get(args.host.rstrip('/')+'/metrics/recent',params={'limit':5000,'run_id':run_id},headers={'X-API-Key':args.api_key},timeout=20)
                r.raise_for_status(); metrics=r.json().get('metrics',[])
            except Exception as exc:
                metric_error=f'{type(exc).__name__}: {exc}'
            metric_path=Path(str(prefix)+'_stage_metrics.json')
            metric_path.write_text(json.dumps({'run_id':run_id,'metrics':metrics,'retrieval_error':metric_error},indent=2),encoding='utf-8')

            stats_path=Path(str(prefix)+'_stats.csv')
            agg={}
            if stats_path.exists():
                with stats_path.open(encoding='utf-8-sig') as fh:
                    for row in csv.DictReader(fh):
                        if row.get('Name')=='Aggregated': agg=row; break
            def f(name):
                try: return float(agg.get(name,''))
                except: return None
            def stage(name):
                vals=[float(m[name]) for m in metrics if m.get(name) is not None]
                return round(mean(vals),4) if vals else None
            summary.append({
                'run_id':run_id,'users':users,'repeat':rep,'wall_duration_s':round(ended-started,3),'locust_exit_code':proc.returncode,
                'requests':int(float(agg.get('Request Count',0) or 0)),'failures':int(float(agg.get('Failure Count',0) or 0)),
                'requests_per_s':f('Requests/s'),'avg_response_ms':f('Average Response Time'),'median_response_ms':f('Median Response Time'),
                'p95_response_ms':f('95%'),'p99_response_ms':f('99%'),'max_response_ms':f('Max Response Time'),
                'avg_t_san_ms':stage('t_san_ms'),'avg_t_score_ms':stage('t_score_ms'),'avg_t_db_ms':stage('t_db_ms'),'avg_t_total_ms':stage('t_total_ms'),
                'stage_metric_count':len(metrics),'metric_retrieval_error':metric_error or '',
            })
            Path(root/'matrix_runs.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
            time.sleep(args.cooldown_seconds)

    fields=list(summary[0].keys()) if summary else []
    with (root/'matrix_runs.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=fields); w.writeheader(); w.writerows(summary)
    print(f'\nCompleted {len(summary)} runs. Summary: {root/"matrix_runs.csv"}')

if __name__=='__main__': main()
