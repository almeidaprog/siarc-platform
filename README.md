# SIARC — Sistema Inteligente de Auditoria e Resiliência Cibernética

> Orquestração de Governança e Defesa Ativa contra Vírus Mutáveis e Exploits via n8n

---

## O que é o SIARC?

O SIARC é uma plataforma de pesquisa aplicada em segurança cibernética que combina:

- **Governança de dados (LGPD)** — sanitização e controle de dados pessoais em logs de segurança
- **Motor de risco com XAI** — score 0–100 com explicações auditáveis por fator
- **Orquestração via n8n** — workflows de ingestão e roteamento de eventos
- **Trilha de auditoria** — registro imutável de todas as operações (LGPD Art. 37)
- **API REST** — integração com qualquer SIEM ou sistema de monitoramento

O projeto segue um cronograma de sprints mensais, evoluindo de um sandbox de governança (Abril/2026) até um sistema de detecção e resposta ativa com ML (fases futuras).

---

## Arquitetura

```
┌────────────────────────────────────────────────────────────┐
│                        n8n (porta 5678)                     │
│  Webhook ─► Análise LGPD+Risco ─► IF(score≥80) ─► Resposta │
└──────────────────────┬─────────────────────────────────────┘
                       │ HTTP POST /analyze
┌──────────────────────▼─────────────────────────────────────┐
│                  SIARC API (porta 8080)                      │
│                                                              │
│  POST /analyze          ← pipeline completo                  │
│  GET  /governance/policies  ← políticas LGPD                 │
│  GET  /governance/report    ← relatório de conformidade      │
│  GET  /audit/entries        ← trilha de auditoria            │
│  GET  /audit/summary        ← estatísticas de auditoria      │
└──────────────────────┬─────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │  scripts/               │  data/
          │  ├─ lgpd_engine.py      │  ├─ governance_policies.json
          │  ├─ risk_engine.py      │  ├─ audit_log.jsonl
          │  ├─ audit_trail.py      │  └─ sample_logs/
          │  ├─ siarc_api.py        │      ├─ network_events.jsonl
          │  └─ log_governance.py   │      └─ maio_events.jsonl
          └─────────────────────────┘
```

---

## Pré-requisitos

| Ferramenta | Versão mínima | Uso |
|---|---|---|
| Docker Desktop | 24+ | Containers n8n + API |
| Docker Compose | v2 (integrado) | Orquestração local |
| Python | 3.12+ | Execução local sem Docker |

---

## Subir o ambiente completo (Docker)

```bash
# 1. Clone ou acesse o diretório do projeto
cd siarc-platform

# 2. Crie o arquivo de variáveis de ambiente
cp .env.example .env

# 3. (Opcional) Edite .env com uma chave de encriptação real
#    N8N_ENCRYPTION_KEY deve ter 32+ caracteres

# 4. Suba os serviços
docker compose up --build

# 5. Verifique os serviços
curl http://localhost:8080/health
```

**URLs dos serviços:**

| Serviço | URL |
|---|---|
| n8n (interface web) | http://localhost:5678 |
| SIARC API | http://localhost:8080 |
| Documentação OpenAPI | http://localhost:8080/docs |
| Redoc | http://localhost:8080/redoc |

---

## Executar localmente sem Docker

```bash
# Instalar dependências
pip install -r requirements.txt

# Rodar a API
uvicorn scripts.siarc_api:app --host 0.0.0.0 --port 8080 --reload

# Processar logs em lote (modo offline)
python scripts/log_governance.py
```

---

## Importar workflows no n8n

1. Acesse http://localhost:5678 e crie um usuário local
2. Vá em **Workflows → Import from File**
3. Importe o workflow da sprint desejada:

| Sprint | Arquivo | Descrição |
|---|---|---|
| Abril/2026 | `workflows/siarc_abril_ingestao_governanca_n8n.json` | Ingestão básica → API → Resposta |
| Maio/2026 | `workflows/siarc_maio_governanca_lgpd_n8n.json` | LGPD + Risco XAI + Roteamento por criticidade |

4. Ative o workflow clicando no toggle superior direito

---

## Testar a API

### Health check
```bash
curl http://localhost:8080/health
```

### Análise completa com LGPD + risco
```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-13T03:15:00-03:00",
    "src_ip": "203.0.113.42",
    "dst_ip": "10.0.0.15",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE-2024-3094 shellcode injection; privilege escalation attempt; mimikatz",
    "user_email": "admin@empresa.com.br",
    "cpf": "321.654.987-11"
  }'
```

**Resposta esperada:**
```json
{
  "event_id": "uuid-gerado",
  "sanitized_event": {
    "user_email": "[PSE_FIEL_abc123de]",
    "cpf": "[CPF_REDACTED]",
    "payload": "CVE-2024-3094 shellcode injection; privilege escalation attempt; mimikatz"
  },
  "governance": {
    "compliance_status": "CONFORME_LGPD",
    "legal_basis": "PESQUISA_DE_SEGURANCA",
    "pii_count": 2,
    "principles_evaluated": { "finalidade": true, "seguranca": true, ... }
  },
  "risk_assessment": {
    "score": 100,
    "level": "CRÍTICO",
    "recommended_action": "RESPONDER — Isolar ativo afetado e iniciar plano de resposta a incidente.",
    "xai_explanation": [
      "[severidade] Severidade 'critical' → 90 pts",
      "[tipo_de_evento] Tipo 'exploit_attempt' → 45 pts",
      "[indicadores_de_ameaca] Indicadores: cve, escalation, mimikatz, privilege, shellcode → 25 pts (máx. 25)",
      "[origem_ip] IP 203.0.113.42 classificado como 'external' → 15 pts",
      "[anomalia_temporal] Evento às 03h (fora do expediente) → 8 pts"
    ]
  }
}
```

### Testar via n8n
```bash
curl -X POST http://localhost:5678/webhook/siarc/evento-governanca \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-13T02:00:00-03:00",
    "src_ip": "10.0.0.55",
    "dst_ip": "10.0.0.1",
    "event_type": "credential_abuse",
    "severity": "high",
    "payload": "brute force SSH; 500 tentativas em 1 minuto"
  }'
```

### Consultar políticas de governança
```bash
curl http://localhost:8080/governance/policies
```

### Consultar trilha de auditoria
```bash
curl http://localhost:8080/audit/entries?limit=10
curl http://localhost:8080/audit/summary
```

### Relatório de conformidade LGPD
```bash
curl http://localhost:8080/governance/report
```

---

## Estrutura de arquivos

```
siarc-platform/
├── .env.example                    ← template de variáveis de ambiente
├── .env                            ← variáveis locais (não commitar)
├── docker-compose.yml              ← orquestração Docker
├── Dockerfile                      ← imagem da SIARC API
├── requirements.txt                ← dependências Python
│
├── scripts/
│   ├── siarc_api.py                ← API FastAPI (endpoints REST)
│   ├── lgpd_engine.py              ← motor de governança LGPD completo
│   ├── risk_engine.py              ← scoring multifatorial + XAI
│   ├── audit_trail.py              ← trilha de auditoria (Art. 37)
│   └── log_governance.py           ← processamento em lote de logs .jsonl
│
├── data/
│   ├── governance_policies.json    ← políticas LGPD configuráveis
│   ├── audit_log.jsonl             ← trilha de auditoria (gerado em runtime)
│   ├── processed_events.json       ← saída do processamento em lote
│   └── sample_logs/
│       ├── network_events.jsonl    ← logs de teste (Sprint Abril)
│       └── maio_events.jsonl       ← logs de teste (Sprint Maio)
│
├── workflows/
│   ├── siarc_abril_ingestao_governanca_n8n.json   ← workflow Sprint Abril
│   └── siarc_maio_governanca_lgpd_n8n.json        ← workflow Sprint Maio
│
└── docs/
    ├── ABRIL_IMPLEMENTADO.md       ← relatório Sprint Abril
    ├── MAIO_IMPLEMENTADO.md        ← relatório Sprint Maio
    └── REVISAO_BIBLIOGRAFICA_ABRIL.md
```

---

## Cronograma de sprints

| Mês | Sprint | Status |
|---|---|---|
| Abril/2026 | Ambiente sandbox + ingestão + LGPD básica | ✅ Concluído |
| Maio/2026 | Camada LGPD completa + risco XAI + auditoria Art. 37 | ✅ Concluído |
| Junho/2026 | Detecção comportamental de malwares mutáveis | Planejado |
| Julho/2026 | Resposta ativa: isolamento automático de hosts | Planejado |
| Agosto/2026 | Dashboard de monitoramento + alertas em tempo real | Planejado |
| Setembro/2026 | ML para detecção de anomalias | Planejado |

---

## Conformidade LGPD

O SIARC foi projetado com LGPD-by-design:

- **Art. 5, I** — Dados pessoais identificados e mascarados antes do armazenamento
- **Art. 6** — Todos os 10 princípios avaliados por evento processado
- **Art. 7** — Base legal explícita para cada operação de tratamento
- **Art. 37** — Trilha de auditoria imutável em `data/audit_log.jsonl`

Dados pessoais suportados: email, CPF, CNPJ, RG, telefone, IP privado (identificação indireta).

Estratégias de mascaramento:
- **Pseudonimização** — hash SHA-256 determinístico (email, IP privado, campos sensíveis por nome)
- **Redação total** — substituição completa (CPF, RG)
- **Mascaramento parcial** — primeiros/últimos caracteres visíveis (CNPJ, telefone)

---

## Referências

- BRASIL. Lei Geral de Proteção de Dados Pessoais. Lei nº 13.709/2018.
- ANDERSON, Ross. Security Engineering. 3. ed. Wiley, 2020.
- TIRONE, Michele et al. Explainable Artificial Intelligence for Cyber Security. Springer, 2022.
- MITRE ATT&CK Framework. https://attack.mitre.org
