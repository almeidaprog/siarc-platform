"""Blind proxy validation of the SIARC rule score on UNSW-NB15.

Ground-truth fields (label/attack_cat) are NEVER used to build the SIARC input.
They are read only after the risk score has been produced, for evaluation.
This provides an external, dataset-derived effectiveness check while preserving
scientific separation between a hand-crafted rule score and machine learning.
"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import argparse, csv, json, math
from collections import Counter, defaultdict
from pathlib import Path
import pandas as pd
from scripts.risk_engine import calculate_risk


def num(row,key,default=0.0):
    try:
        x=float(row.get(key,default))
        return x if math.isfinite(x) else default
    except Exception:
        return default


def blind_event(row, i):
    # IMPORTANT: this function intentionally does not read label or attack_cat.
    service=str(row.get('service','-')).lower()
    state=str(row.get('state','')).upper()
    rate=num(row,'rate'); sbytes=num(row,'sbytes'); dbytes=num(row,'dbytes')
    ct_src_ltm=num(row,'ct_src_ltm'); ct_dst_sport_ltm=num(row,'ct_dst_sport_ltm')
    ct_dst_src_ltm=num(row,'ct_dst_src_ltm'); ct_srv_dst=num(row,'ct_srv_dst')

    signals=[]
    scan = ct_dst_sport_ltm >= 6 or ct_dst_src_ltm >= 15
    brute = service in {'ssh','ftp','ftp-data'} and ct_src_ltm >= 8
    exfil = sbytes >= 500_000 and sbytes >= 5*(dbytes+1)
    flood = rate >= 10_000 or (rate >= 2_000 and ct_srv_dst >= 20)
    suspicious_state = state in {'INT','REQ','RST','ECO','PAR','URN'} and rate >= 500

    if scan: signals.append('scan')
    if brute: signals.append('brute')
    if exfil: signals.append('exfiltration')
    if flood: signals.append('rate_anomaly')
    if suspicious_state: signals.append('state_anomaly')

    if exfil: event_type='data_exfiltration'
    elif brute: event_type='brute_force'
    elif scan: event_type='port_scan'
    elif flood and suspicious_state: event_type='exploit_attempt'
    else: event_type='unknown'

    n=len(signals)
    severity='low' if n==0 else ('medium' if n==1 else ('high' if n==2 else 'critical'))
    payload=(f"UNSW blind flow proto={row.get('proto')} service={service} state={state} "
             f"signals={'|'.join(signals) if signals else 'none'}")
    return {'timestamp':'2026-09-01T12:00:00','src_ip':f'10.99.{(i//250)%250}.{(i%250)+1}',
            'dst_ip':'192.168.99.10','event_type':event_type,'severity':severity,'payload':payload,
            'extra':{'dataset':'UNSW-NB15','blind_adapter_version':'1.0'}}


def safe(a,b): return a/b if b else 0.0

def auc_rank(scores, labels):
    pairs=sorted(zip(scores,labels), key=lambda x:x[0])
    n_pos=sum(labels); n_neg=len(labels)-n_pos
    if not n_pos or not n_neg: return None
    # Average ranks for ties.
    rank_sum=0.0; i=0; rank=1
    while i<len(pairs):
        j=i
        while j+1<len(pairs) and pairs[j+1][0]==pairs[i][0]: j+=1
        avg=(rank + (rank+(j-i)))/2
        rank_sum += avg*sum(pairs[k][1] for k in range(i,j+1))
        rank += (j-i+1); i=j+1
    return (rank_sum - n_pos*(n_pos+1)/2)/(n_pos*n_neg)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--csv',default='data/UNSW_NB15_testing-set.csv')
    ap.add_argument('--rows',type=int,default=10000)
    ap.add_argument('--threshold',type=int,default=60,help='Score >= threshold predicts attack')
    args=ap.parse_args()
    df=pd.read_csv(args.csv,nrows=args.rows)
    if 'label' not in df.columns: raise SystemExit('Dataset must contain the UNSW-NB15 label column.')

    tp=fp=tn=fn=0; scores=[]; labels=[]; per_cat=defaultdict(Counter); rows=[]
    for i,(_,row) in enumerate(df.iterrows()):
        event=blind_event(row,i)
        risk=calculate_risk(event)
        truth=int(row.get('label',0)); pred=int(risk.score>=args.threshold)
        scores.append(risk.score); labels.append(truth)
        if truth and pred: tp+=1
        elif not truth and pred: fp+=1
        elif not truth and not pred: tn+=1
        else: fn+=1
        cat=str(row.get('attack_cat','Normal'))
        per_cat[cat]['total']+=1; per_cat[cat]['detected']+=int(pred)
        rows.append({'index':i,'truth':truth,'attack_cat':cat,'score':risk.score,'level':risk.level,'prediction':pred,
                     'event_type':event['event_type'],'severity':event['severity']})

    precision=safe(tp,tp+fp); recall=safe(tp,tp+fn); specificity=safe(tn,tn+fp); f1=safe(2*precision*recall,precision+recall)
    report={
        'evaluation':'Blind UNSW-NB15 binary proxy validation', 'rows':len(rows), 'threshold':args.threshold,
        'confusion_matrix':{'tp':tp,'fp':fp,'tn':tn,'fn':fn},
        'precision':round(precision,6),'recall':round(recall,6),'specificity':round(specificity,6),
        'f1':round(f1,6),'balanced_accuracy':round((recall+specificity)/2,6),
        'roc_auc_score': None if auc_rank(scores,labels) is None else round(auc_rank(scores,labels),6),
        'per_attack_category_detection_rate':{k:round(safe(v['detected'],v['total']),6) for k,v in sorted(per_cat.items())},
        'leakage_control':'label and attack_cat are not read by blind_event(); they are used only after scoring for evaluation.',
        'scope_note':'This is a proxy effectiveness experiment for the current rule pipeline, not a trained ML classifier.'
    }
    out=Path('results/jisa/score_unsw'); out.mkdir(parents=True,exist_ok=True)
    (out/'score_unsw_blind_validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    with (out/'score_unsw_predictions.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.DictWriter(fh,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
