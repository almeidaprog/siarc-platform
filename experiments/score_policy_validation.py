"""Validate SIARC score decisions against an explicit expert-policy scenario set.

This is a policy-conformance test: it checks whether representative scenarios are
assigned to the intended operational risk class and whether risk is monotonic when
threat evidence is added. It does NOT claim malware-detection accuracy.
"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import csv, json
from collections import Counter
from pathlib import Path
from scripts.risk_engine import calculate_risk

CASES=[]
def add(cid,expected,event): CASES.append((cid,expected,event))

# Low-risk routine events.
for i in range(12):
    add(f'low-{i:02d}','BAIXO',{'timestamp':f'2026-09-{(i%9)+1:02d}T12:00:00','src_ip':'127.0.0.1','event_type':'unknown','severity':'low','payload':'routine health event'})
# Medium: one moderate factor, no strong threat evidence.
for i in range(12):
    add(f'medium-{i:02d}','MÉDIO',{'timestamp':f'2026-09-{(i%9)+1:02d}T12:00:00','src_ip':'127.0.0.1','event_type':'unknown','severity':'medium','payload':'routine operational anomaly'})
# High: combinations that require active analyst attention but not isolation.
for i in range(12):
    add(f'high-{i:02d}','ALTO',{'timestamp':f'2026-09-{(i%9)+1:02d}T12:00:00','src_ip':'10.0.0.20','event_type':'port_scan','severity':'medium','payload':'repeated connection attempts'})
# Critical: explicit strong threat evidence.
for i in range(12):
    add(f'critical-{i:02d}','CRÍTICO',{'timestamp':f'2026-09-{(i%9)+1:02d}T03:00:00','src_ip':'203.0.113.88','event_type':'exploit_attempt','severity':'high','payload':'CVE shellcode privilege escalation exploit'})

ORDER={'BAIXO':0,'MÉDIO':1,'ALTO':2,'CRÍTICO':3}


def safe_div(a,b): return a/b if b else 0.0

def main():
    outdir=Path('results/jisa/score_policy'); outdir.mkdir(parents=True,exist_ok=True)
    rows=[]; conf=Counter()
    for cid,expected,event in CASES:
        r=calculate_risk(event)
        conf[(expected,r.level)]+=1
        rows.append({'id':cid,'expected_level':expected,'predicted_level':r.level,'score':r.score,'correct':expected==r.level})

    labels=list(ORDER)
    per={}; f1s=[]
    for lab in labels:
        tp=conf[(lab,lab)]
        fp=sum(v for (e,p),v in conf.items() if p==lab and e!=lab)
        fn=sum(v for (e,p),v in conf.items() if e==lab and p!=lab)
        precision=safe_div(tp,tp+fp); recall=safe_div(tp,tp+fn); f1=safe_div(2*precision*recall,precision+recall)
        per[lab]={'tp':tp,'fp':fp,'fn':fn,'precision':round(precision,6),'recall':round(recall,6),'f1':round(f1,6)}; f1s.append(f1)

    # Monotonicity: adding explicit threat evidence must not reduce the score.
    base={'timestamp':'2026-09-01T12:00:00','src_ip':'10.0.0.5','event_type':'unknown','severity':'low','payload':''}
    sequence=[
        base,
        {**base,'severity':'medium'},
        {**base,'severity':'medium','event_type':'port_scan'},
        {**base,'severity':'high','event_type':'exploit_attempt','payload':'exploit shellcode'},
        {**base,'severity':'critical','event_type':'exploit_attempt','payload':'zero-day CVE shellcode privilege escalation'},
    ]
    scores=[calculate_risk(e).score for e in sequence]
    monotonic=all(b>=a for a,b in zip(scores,scores[1:]))

    report={
        'evaluation':'Expert-policy score validation',
        'cases':len(rows),
        'accuracy':round(sum(r['correct'] for r in rows)/len(rows),6),
        'macro_f1':round(sum(f1s)/len(f1s),6),
        'per_level':per,
        'monotonicity_passed':monotonic,
        'monotonicity_scores':scores,
        'scope_note':'Measures conformance to the stated operational risk policy, not external intrusion-detection accuracy.'
    }
    (outdir/'score_policy_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    with (outdir/'score_policy_cases.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
