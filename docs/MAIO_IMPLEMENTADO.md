# SIARC — Entrega Técnica de Maio/2026

**Sprint:** Desenvolvimento da Camada de Governança de Dados (Filtros LGPD)
**Status:** Concluído

---

## Objetivo da Sprint

Implementar a camada completa de governança de dados conforme Lei nº 13.709/2018 (LGPD), com:
- Detecção e mascaramento de múltiplos tipos de dados pessoais
- Avaliação dos 10 princípios do Art. 6
- Trilha de auditoria imutável (Art. 37)
- Motor de risco multifatorial com explicações XAI
- API expandida com endpoints de governança e conformidade

---

## Componentes entregues

### 1. `scripts/lgpd_engine.py` — Motor de Governança LGPD

Motor central de conformidade. Implementa:

**Detecção de PII por regex:**
| Tipo | Categoria | Estratégia | Art. LGPD |
|---|---|---|---|
| E-mail | Dado Pessoal | Pseudonimização | Art. 5, I |
| CPF | Dado Pessoal | Redação total | Art. 5, I |
| CNPJ | Dado Pessoal | Mascaramento parcial | Art. 5, I |
| RG | Dado Pessoal | Redação total | Art. 5, I |
| Telefone BR | Dado Pessoal | Mascaramento parcial | Art. 5, I |
| IP privado | Dado Pessoal | Pseudonimização | Art. 5, I (id. indireta) |

**Campos sensíveis por nome** (cpf, email, senha, token, etc.) → pseudonimização automática.

**Avaliação dos 10 princípios (Art. 6):**
finalidade, adequação, necessidade, livre acesso, qualidade dos dados, transparência, segurança, prevenção, não discriminação, responsabilização.

**Saída:** `GovernanceDecision` com decisão completa, documentada e serializável.

---

### 2. `scripts/risk_engine.py` — Motor de Risco com XAI

Scoring multifatorial 0–100 com explicações legíveis por fator:

| Fator | Peso máximo | Descrição |
|---|---|---|
| Severidade | 90 pts | low=15, medium=35, high=65, critical=90 |
| Tipo de evento | 55 pts | exploit_attempt=45, ransomware=55, etc. |
| Indicadores textuais | 25 pts | CVE, shellcode, mimikatz, polymorphic, etc. |
| Origem do IP | 15 pts | external=15, internal=5, loopback=0 |
| Anomalia temporal | 8 pts | Eventos fora do horário comercial (06h–22h) |

**Níveis de risco e ações recomendadas:**
| Score | Nível | Ação |
|---|---|---|
| 0–29 | BAIXO | MONITORAR |
| 30–59 | MÉDIO | INVESTIGAR |
| 60–79 | ALTO | ALERTAR |
| 80–100 | CRÍTICO | RESPONDER |

---

### 3. `scripts/audit_trail.py` — Trilha de Auditoria

Registro append-only em `data/audit_log.jsonl`, conforme LGPD Art. 37.

Cada entrada contém:
```json
{
  "audit_timestamp": "2026-05-13T12:00:00Z",
  "event_id": "uuid",
  "action": "FULL_ANALYSIS",
  "actor": "siarc-api",
  "outcome": "SUCCESS",
  "lgpd_reference": "Lei 13.709/2018 — Art. 37",
  "details": { "pii_count": 2, "risk_score": 95, "risk_level": "CRÍTICO" }
}
```

---

### 4. `scripts/siarc_api.py` — API Expandida (v0.2.0)

Novos endpoints adicionados à API:

| Método | Endpoint | Descrição |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/analyze` | Pipeline completo: LGPD + risco + auditoria |
| GET | `/governance/policies` | Lista políticas LGPD ativas |
| GET | `/governance/report` | Relatório de conformidade |
| GET | `/audit/entries` | Entradas recentes da trilha |
| GET | `/audit/summary` | Estatísticas da trilha |

Documentação interativa disponível em `http://localhost:8080/docs`.

---

### 5. `data/governance_policies.json` — Políticas LGPD Configuráveis

6 políticas definidas:
- **POL-001** — Mascaramento de dados pessoais em logs
- **POL-002** — Retenção (90 dias eventos / 5 anos auditoria)
- **POL-003** — Base legal de tratamento
- **POL-004** — Minimização de dados (campos essenciais)
- **POL-005** — Trilha de auditoria obrigatória
- **POL-006** — Avaliação dos 10 princípios Art. 6

---

### 6. `workflows/siarc_maio_governanca_lgpd_n8n.json` — Workflow n8n Maio

Workflow de 7 nós com roteamento por criticidade:

```
Webhook ──► HTTP /analyze ──► IF(score≥80) ──┬──► Enriquecer [ALERTA_CRITICO] ──► Responder
                                              └──► Enriquecer [ROTINA] ──────────► Responder
```

**Endpoint do webhook:** `POST http://localhost:5678/webhook/siarc/evento-governanca`

---

### 7. `data/sample_logs/maio_events.jsonl` — Eventos de Teste Maio

6 eventos cobrindo cenários avançados:
- Exploit CVE-2024-3094 com shellcode (crítico, 03h, IP externo)
- Movimento lateral via SMB com mimikatz (alto)
- Ransomware polimórfico com C2 beacon (crítico)
- Brute force SSH interno (médio)
- Exfiltração via DNS tunneling com base64 (alto)
- Port scan interno de rotina (baixo)

---

## Como executar a sprint de Maio

### 1. Subir ambiente

```bash
cp .env.example .env
docker compose up --build
```

### 2. Testar o pipeline completo

```bash
# Evento crítico com múltiplos dados pessoais
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-13T03:22:11-03:00",
    "src_ip": "203.0.113.42",
    "dst_ip": "10.0.0.15",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE-2024-3094 shellcode injection; privilege escalation; mimikatz",
    "user_email": "admin@empresa.com.br",
    "cpf": "321.654.987-11"
  }'
```

### 3. Testar via n8n

```bash
# Importar siarc_maio_governanca_lgpd_n8n.json e ativar o workflow

curl -X POST http://localhost:5678/webhook/siarc/evento-governanca \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-13T14:00:00-03:00",
    "src_ip": "10.0.0.55",
    "event_type": "credential_abuse",
    "severity": "high",
    "payload": "brute force SSH; 500 tentativas"
  }'
```

### 4. Consultar conformidade

```bash
# Políticas ativas
curl http://localhost:8080/governance/policies

# Relatório de conformidade LGPD
curl http://localhost:8080/governance/report

# Trilha de auditoria (últimas 10 entradas)
curl "http://localhost:8080/audit/entries?limit=10"

# Resumo estatístico
curl http://localhost:8080/audit/summary
```

### 5. Processar logs de maio em lote

```bash
# Dentro do container ou localmente
python -c "
from scripts.log_governance import process_events
import json, pathlib
lines = pathlib.Path('data/sample_logs/maio_events.jsonl').read_text().splitlines()
results = process_events(lines)
print(json.dumps(results, ensure_ascii=False, indent=2))
"
```

---

## O que mudou em relação a Abril

| Capacidade | Abril | Maio |
|---|---|---|
| Tipos de PII detectados | email, CPF | + CNPJ, RG, telefone, IP privado |
| Estratégias de mascaramento | redação | + pseudonimização, mascaramento parcial |
| Avaliação princípios LGPD | — | 10 princípios Art. 6 |
| Motor de risco | 3 fatores | 5 fatores + cap + XAI completo |
| Indicadores de ameaça | 7 tokens | 25+ indicadores com pesos individuais |
| Trilha de auditoria | — | Art. 37 completo |
| Endpoints de governança | — | /governance/policies, /governance/report |
| Endpoints de auditoria | — | /audit/entries, /audit/summary |
| Workflow n8n | 3 nós | 7 nós com roteamento por criticidade |
| Políticas configuráveis | — | 6 políticas em governance_policies.json |
| Documentação API | — | OpenAPI em /docs |

---

## Próximas sprints

**Junho/2026 — Detecção comportamental de malwares mutáveis:**
- Fingerprinting de comportamento por sequência de eventos
- Detecção de hash polimórfico (múltiplos eventos do mesmo binário)
- Correlação temporal de eventos (janela deslizante)
- Score de anomalia comportamental

**Julho/2026 — Resposta ativa:**
- Webhook de isolamento de host (integração com firewall via API)
- Playbooks de resposta automática no n8n
- Notificações (email/Slack) para eventos críticos

---

## Limite honesto da entrega

Esta sprint consolida a camada de governança. O que **ainda não está implementado**:
- Detecção real de malware (análise de binários)
- Isolamento automático de hosts comprometidos
- Dashboard de visualização em tempo real
- Machine learning para anomaly detection
- Integração com SIEM externo (Wazuh, Splunk)
- Autenticação na API (JWT/OAuth2)
