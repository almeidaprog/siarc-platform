"""Build a deterministic synthetic PII validation corpus for SIARC.

The corpus contains no real personal data. CPF/CNPJ values are synthetically
constructed with valid check digits so that regex-only matching is not confused
with semantic validity.
"""
from __future__ import annotations
import json, random
from pathlib import Path

SEED = 20260901
random.seed(SEED)


def cpf_from_base(base9: str) -> str:
    nums=[int(x) for x in base9]
    for pos in (9,10):
        weight=pos+1
        total=sum(nums[i]*(weight-i) for i in range(pos))
        nums.append((total*10%11)%10)
    d=''.join(map(str,nums))
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


def cnpj_from_base(base12: str) -> str:
    nums=[int(x) for x in base12]
    for weights in ([5,4,3,2,9,8,7,6,5,4,3,2],[6,5,4,3,2,9,8,7,6,5,4,3,2]):
        total=sum(n*w for n,w in zip(nums,weights))
        rem=total%11
        nums.append(0 if rem<2 else 11-rem)
    d=''.join(map(str,nums))
    return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"

cases=[]

def add(cid,event,expected,notes=''):
    cases.append({'id':cid,'event':event,'expected':expected,'notes':notes})

for i in range(20):
    v=f"synthetic.user{i:02d}@example.org"
    add(f"email-{i:02d}", {'payload':f"authentication subject={v} result=ok"}, [{'type':'email','value':v}])

for i in range(15):
    base=f"{123450000+i:09d}"
    v=cpf_from_base(base)
    add(f"cpf-{i:02d}", {'payload':f"document={v} source=fixture"}, [{'type':'cpf','value':v}])

for i in range(10):
    base=f"{120000000001+i:012d}"
    v=cnpj_from_base(base)
    add(f"cnpj-{i:02d}", {'payload':f"organization_id={v}"}, [{'type':'cnpj','value':v}])

for i in range(15):
    ddd=11+(i%8)
    v=f"({ddd}) 9{7000+i:04d}-{1000+i:04d}"
    add(f"phone-{i:02d}", {'payload':f"callback={v}"}, [{'type':'phone_br','value':v}])

for i in range(10):
    v=f"{10+i%9}.{100+i:03d}.{200+i:03d}-{i%10}"
    add(f"rg-{i:02d}", {'payload':f"rg={v}"}, [{'type':'rg','value':v}])

for i in range(15):
    v=f"10.{10+i}.{20+i}.{30+i}"
    add(f"private-ip-{i:02d}", {'payload':f"internal_client={v}"}, [{'type':'ip_private','value':v}])

for i in range(10):
    v=f"synthetic-login-{i:02d}"
    add(f"sensitive-field-{i:02d}", {'username':v}, [{'type':'nome_de_campo_sensivel','value':v}])

# Mixed / nested cases exercise recursion and multiple PII per event.
for i in range(10):
    email=f"nested{i}@example.net"
    ip=f"192.168.{i+1}.{i+10}"
    add(f"nested-{i:02d}", {'extra':{'contacts':[email, {'origin':ip}]}}, [
        {'type':'email','value':email}, {'type':'ip_private','value':ip}
    ])

negative_payloads=[
    'CVE-2024-3094 severity=high',
    'public_ip=203.0.113.88',
    'public_ip=198.51.100.42',
    'uuid=550e8400-e29b-41d4-a716-446655440000',
    'timestamp=2026-09-01T12:34:56Z',
    'sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'order=1234567890',
    'port=5432 pid=12345',
    'version=10.20.30',
    'invalid_private_ip=10.999.1.1',
    'invalid_cpf=111.111.111-11',
    'invalid_cnpj=11.111.111/1111-11',
    'text without identifiers',
    'user agent Mozilla/5.0',
    'MAC=AA:BB:CC:DD:EE:FF',
    'IPv6 documentation=2001:db8::1',
    'ticket 000123456789',
    'decimal=123.456.789',
    'phone-like short=1234-5678',
    'CNPJ label only, no value',
]
for i,payload in enumerate(negative_payloads):
    add(f"negative-{i:02d}", {'payload':payload}, [], 'negative control')

out={'metadata':{'name':'SIARC synthetic PII effectiveness corpus','seed':SEED,'real_personal_data':False,'cases':len(cases)},'cases':cases}
path=Path('data/evaluation/pii_validation_cases.json')
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
print(path, len(cases))
