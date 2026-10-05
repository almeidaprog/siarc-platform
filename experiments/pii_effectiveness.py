"""Measure SIARC PII sanitization effectiveness on a labeled synthetic corpus.

Outputs precision, recall, F1, false-positive rate, and raw-PII leakage rate.
This evaluates detection/masking quality, not only execution time.
"""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import argparse, csv, json
from collections import Counter, defaultdict

from scripts.lgpd_engine import apply_lgpd_governance


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--corpus', default='data/evaluation/pii_validation_cases.json')
    ap.add_argument('--output-dir', default='results/jisa/pii')
    args=ap.parse_args()

    corpus=json.loads(Path(args.corpus).read_text(encoding='utf-8'))
    outdir=Path(args.output_dir); outdir.mkdir(parents=True,exist_ok=True)

    overall=Counter(); by_type=defaultdict(Counter); failures=[]
    negative_cases=0; negative_cases_with_fp=0; leakage_events=0

    for case in corpus['cases']:
        expected=Counter((x['type'],x['value']) for x in case.get('expected',[]))
        sanitized, decision=apply_lgpd_governance(case['event'], event_id=case['id'])
        observed=Counter((d.pattern_matched,d.original_value) for d in decision.pii_detected)

        tp=sum((expected & observed).values())
        fp=sum((observed - expected).values())
        fn=sum((expected - observed).values())
        overall.update({'tp':tp,'fp':fp,'fn':fn})

        types=set([t for t,_ in expected] + [t for t,_ in observed])
        for typ in types:
            e=Counter({k:v for k,v in expected.items() if k[0]==typ})
            o=Counter({k:v for k,v in observed.items() if k[0]==typ})
            by_type[typ].update({'tp':sum((e&o).values()),'fp':sum((o-e).values()),'fn':sum((e-o).values())})

        if not expected:
            negative_cases += 1
            if fp:
                negative_cases_with_fp += 1

        sanitized_text=json.dumps(sanitized,ensure_ascii=False,sort_keys=True)
        leaked=[value for _,value in expected if value and value in sanitized_text]
        if leaked:
            leakage_events += 1

        if fp or fn or leaked:
            failures.append({
                'id':case['id'], 'notes':case.get('notes',''),
                'expected':[{'type':t,'value':v,'count':c} for (t,v),c in expected.items()],
                'observed':[{'type':t,'value':v,'count':c} for (t,v),c in observed.items()],
                'false_positive_count':fp, 'false_negative_count':fn,
                'leaked_values':leaked,
            })

    p=safe_div(overall['tp'],overall['tp']+overall['fp'])
    r=safe_div(overall['tp'],overall['tp']+overall['fn'])
    f1=safe_div(2*p*r,p+r)
    report={
        'evaluation':'PII sanitization effectiveness',
        'corpus':corpus['metadata'],
        'overall':{
            'tp':overall['tp'],'fp':overall['fp'],'fn':overall['fn'],
            'precision':round(p,6),'recall':round(r,6),'f1':round(f1,6),
            'negative_case_false_positive_rate':round(safe_div(negative_cases_with_fp,negative_cases),6),
            'raw_pii_leakage_event_rate':round(safe_div(leakage_events,len(corpus['cases'])),6),
        },
        'by_type':{},
        'failed_cases':len(failures),
        'scope_note':'Synthetic labeled corpus validates supported PII patterns and masking leakage; it is not a population-wide privacy guarantee.'
    }
    for typ,c in sorted(by_type.items()):
        pp=safe_div(c['tp'],c['tp']+c['fp']); rr=safe_div(c['tp'],c['tp']+c['fn']); ff=safe_div(2*pp*rr,pp+rr)
        report['by_type'][typ]={'tp':c['tp'],'fp':c['fp'],'fn':c['fn'],'precision':round(pp,6),'recall':round(rr,6),'f1':round(ff,6)}

    (outdir/'pii_effectiveness.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (outdir/'pii_failures.json').write_text(json.dumps(failures,ensure_ascii=False,indent=2),encoding='utf-8')
    with (outdir/'pii_by_type.csv').open('w',newline='',encoding='utf-8') as fh:
        w=csv.writer(fh); w.writerow(['pii_type','tp','fp','fn','precision','recall','f1'])
        for typ,m in report['by_type'].items():
            w.writerow([typ,m['tp'],m['fp'],m['fn'],m['precision'],m['recall'],m['f1']])

    print(json.dumps(report,ensure_ascii=False,indent=2))
    if failures:
        print(f"WARNING: {len(failures)} corpus cases need review. See {outdir/'pii_failures.json'}")

if __name__=='__main__':
    main()
