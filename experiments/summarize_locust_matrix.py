"""Aggregate repeated Locust runs by concurrency level with mean and standard deviation."""
from __future__ import annotations
import csv, json, statistics, math
from collections import defaultdict
from pathlib import Path

FIELDS=['requests_per_s','avg_response_ms','median_response_ms','p95_response_ms','p99_response_ms','max_response_ms','avg_t_san_ms','avg_t_score_ms','avg_t_db_ms','avg_t_total_ms']

def main():
    path=Path('results/jisa/locust_matrix/matrix_runs.csv')
    if not path.exists(): raise SystemExit(f'Missing {path}; run run_locust_matrix.py first.')
    rows=list(csv.DictReader(path.open(encoding='utf-8'))); groups=defaultdict(list)
    for r in rows: groups[int(r['users'])].append(r)
    out=[]
    for users,rs in sorted(groups.items()):
        item={'users':users,'repeats':len(rs),'total_requests':sum(int(r['requests']) for r in rs),'total_failures':sum(int(r['failures']) for r in rs)}
        for field in FIELDS:
            vals=[]
            for r in rs:
                try:
                    if r[field] != '': vals.append(float(r[field]))
                except: pass
            item[field+'_mean']=round(statistics.fmean(vals),4) if vals else None
            sd=statistics.stdev(vals) if len(vals)>1 else 0.0 if vals else None
            item[field+'_sd']=round(sd,4) if sd is not None else None
            if len(vals)>1:
                # Two-sided 95% Student-t critical values for common small repeat counts;
                # normal approximation is used only when n is larger than the table.
                tcrit={2:12.706,3:4.303,4:3.182,5:2.776,6:2.571,7:2.447,8:2.365,9:2.306,10:2.262}.get(len(vals),1.96)
                item[field+'_ci95_halfwidth']=round(tcrit*sd/math.sqrt(len(vals)),4)
            else:
                item[field+'_ci95_halfwidth']=None
        item['error_rate_pct']=round(100*item['total_failures']/item['total_requests'],4) if item['total_requests'] else None
        out.append(item)
    root=path.parent
    (root/'matrix_summary.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    with (root/'matrix_summary.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
    print(json.dumps(out,indent=2))

if __name__=='__main__': main()
