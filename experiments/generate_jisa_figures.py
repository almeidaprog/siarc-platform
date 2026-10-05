"""Generate publication-ready figures from final JISA experiment outputs."""
from __future__ import annotations
import csv, json
from pathlib import Path
import matplotlib.pyplot as plt

OUT=Path('results/jisa/figures'); OUT.mkdir(parents=True,exist_ok=True)

def read_csv(path):
    with Path(path).open(encoding='utf-8-sig') as f: return list(csv.DictReader(f))

def nums(rows,key): return [float(r[key]) for r in rows if r.get(key) not in ('',None)]

def main():
    matrix=Path('results/jisa/locust_matrix/matrix_summary.csv')
    if matrix.exists():
        rows=read_csv(matrix); x=[int(r['users']) for r in rows]
        y=[float(r['requests_per_s_mean']) for r in rows]; err=[float(r.get('requests_per_s_ci95_halfwidth') or 0) for r in rows]
        plt.figure(figsize=(6.4,3.8)); plt.errorbar(x,y,yerr=err,marker='o',capsize=3); plt.xlabel('Concurrent users'); plt.ylabel('Throughput (requests/s)'); plt.grid(True,alpha=.25); plt.tight_layout(); plt.savefig(OUT/'throughput_ci95.png',dpi=300); plt.close()
        avg=[float(r['avg_response_ms_mean']) for r in rows]; p95=[float(r['p95_response_ms_mean']) for r in rows]
        plt.figure(figsize=(6.4,3.8)); plt.plot(x,avg,marker='o',label='Average'); plt.plot(x,p95,marker='o',label='P95'); plt.xlabel('Concurrent users'); plt.ylabel('Response time (ms)'); plt.legend(); plt.grid(True,alpha=.25); plt.tight_layout(); plt.savefig(OUT/'latency_curve.png',dpi=300); plt.close()
        tdb=[float(r['avg_t_db_ms_mean']) for r in rows if r.get('avg_t_db_ms_mean') not in ('',None)]; tsan=[float(r['avg_t_san_ms_mean']) for r in rows if r.get('avg_t_san_ms_mean') not in ('',None)]; tscore=[float(r['avg_t_score_ms_mean']) for r in rows if r.get('avg_t_score_ms_mean') not in ('',None)]
        if len(tdb)==len(x):
            plt.figure(figsize=(6.4,3.8)); plt.plot(x,tsan,marker='o',label='Sanitization'); plt.plot(x,tscore,marker='o',label='Scoring'); plt.plot(x,tdb,marker='o',label='PostgreSQL persistence'); plt.yscale('log'); plt.xlabel('Concurrent users'); plt.ylabel('Mean stage time (ms, log scale)'); plt.legend(); plt.grid(True,alpha=.25); plt.tight_layout(); plt.savefig(OUT/'stage_latency.png',dpi=300); plt.close()
    pii=Path('results/jisa/pii/pii_by_type.csv')
    if pii.exists():
        rows=read_csv(pii); labels=[r['pii_type'] for r in rows]; f1=[float(r['f1']) for r in rows]
        plt.figure(figsize=(7.2,3.8)); plt.bar(labels,f1); plt.ylim(0,1.05); plt.ylabel('F1-score'); plt.xticks(rotation=30,ha='right'); plt.tight_layout(); plt.savefig(OUT/'pii_f1_by_type.png',dpi=300); plt.close()
    unsw=Path('results/jisa/score_unsw/score_unsw_blind_validation.json')
    if unsw.exists():
        d=json.loads(unsw.read_text()); cm=d['confusion_matrix']; vals=[[cm['tn'],cm['fp']],[cm['fn'],cm['tp']]]
        plt.figure(figsize=(4.2,3.8)); im=plt.imshow(vals); plt.xticks([0,1],['Pred normal','Pred attack']); plt.yticks([0,1],['True normal','True attack']);
        for i in range(2):
            for j in range(2): plt.text(j,i,str(vals[i][j]),ha='center',va='center')
        plt.title('UNSW-NB15 blind score validation'); plt.tight_layout(); plt.savefig(OUT/'score_confusion_matrix.png',dpi=300); plt.close()
    print(f'Figures saved to {OUT}')

if __name__=='__main__': main()
