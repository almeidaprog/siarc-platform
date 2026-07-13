# SIARC — Entrega Técnica de Julho/2026

**Sprint:** Resposta Ativa — Isolamento Automático de Hosts (simulação)
**Status:** Parcial — apenas a orquestração de resposta ativa via n8n
**Escopo desta entrega:** somente o fluxo de **isolamento simulado**. O algoritmo de *Cyber Security Score* unificado e os endpoints da SIARC API para essa sprint são responsabilidade de outro colaborador e não fazem parte deste documento.

---

## Objetivo da sprint (recorte deste entregável)

Conforme o cronograma do projeto:

> *"Julho/2026: Implementação do algoritmo de Cyber Security Score e fluxos de resposta ativa (isolamento de hosts)."*

Este documento cobre apenas a segunda metade: **fluxos de resposta ativa (isolamento de hosts) em ambiente de sandbox**, atendendo ao objetivo específico do projeto:

> *"Validar a aplicabilidade da resposta ativa (bloqueio automático) em ambiente de sandbox."*

---

## Componente entregue

### `workflows/siarc_julho_isolamento_resposta_ativa_n8n.json`

Workflow n8n de 6 nós, desacoplado da SIARC API e do cálculo de score:

```
Webhook ──► IF(score≥80 OU verdict/level crítico OU zero-day)
                 ├─ TRUE  ──► Simular Isolamento de Host (Playbook) ──► Responder
                 └─ FALSE ──► Não Isolar — Manter Monitoramento ────► Responder
```

**Endpoint:** `POST http://localhost:5678/webhook/siarc/host-isolation`

**Contrato de entrada** — este workflow **não calcula** score. Ele espera um evento já pontuado por outro fluxo (ex.: saída do `/analyze/exploit` de Junho ou do motor de risco de Maio):

```json
{
  "event_id": "evt-iso-001",
  "src_ip": "203.0.113.88",
  "verdict": "EXPLOIT_CRITICO",
  "score": 92,
  "is_zero_day": true
}
```

Campos aceitos de forma flexível para compatibilidade com os dois motores existentes: `score` / `exploit_score` / `risk_score`, e `verdict` / `level` (o motor de risco de Maio usa `level`, o de exploits de Junho usa `verdict`).

**Limiar de resposta ativa (combinador OR):**
| Condição | Origem |
|---|---|
| `score >= 80` | qualquer motor de score |
| `verdict == "EXPLOIT_CRITICO"` | `exploit_analyzer.py` (Junho) |
| `level == "CRÍTICO"` | `risk_engine.py` (Maio) |
| `is_zero_day == true` | `exploit_analyzer.py` (Junho) |

**Ticket de isolamento simulado (ramo TRUE):**
```json
{
  "isolation_id": "ISO-...",
  "host": "203.0.113.88",
  "status": "ISOLADO_SANDBOX",
  "simulated": true,
  "isolated_at": "2026-07-13T...",
  "ttl_hours": 4,
  "expires_at": "2026-07-13T...",
  "requires_human_review": true,
  "firewall_rules_simulated": [
    "DROP ALL FROM 203.0.113.88",
    "DROP ALL TO 203.0.113.88",
    "ALLOW mgmt-gateway <-> 203.0.113.88"
  ],
  "playbook": [
    "1. Bloquear host ... no firewall perimetral (DROP ALL INBOUND/OUTBOUND)",
    "2. Permitir apenas trafego do gateway de gestao do SOC (allowlist)",
    "3. Revogar sessoes e tokens ativos associados ao host",
    "4. Disparar snapshot de memoria/disco para analise forense",
    "5. Notificar equipe SOC e abrir ticket de resposta a incidente",
    "6. Reavaliacao humana obrigatoria em ate 4h (expira em ...)"
  ],
  "xai_explanation": ["[DECISAO] ...", "[ACAO] Isolamento SIMULADO...", "[REVISAO] ..."]
}
```

**Por que "simulado" e não real:** o objetivo específico do projeto pede validação em **ambiente de sandbox**, não integração com firewall/EDR de produção. O workflow gera o playbook de resposta e as regras que *seriam* aplicadas, com TTL e exigência de revisão humana antes de qualquer liberação ou escalonamento — sem executar nenhuma alteração real de rede.

---

### `data/sample_logs/julho_isolation_events.jsonl`

5 eventos pré-pontuados cobrindo os dois ramos do workflow:

| Evento | score | verdict/level | Resultado esperado |
|---|---|---|---|
| evt-iso-001 | 92 | EXPLOIT_CRITICO + zero-day | ISOLADO_SANDBOX |
| evt-iso-002 | 85 | CRÍTICO (level) | ISOLADO_SANDBOX |
| evt-iso-003 | 65 | EXPLOIT_CONFIRMADO | MONITORAMENTO |
| evt-iso-004 | 30 | SUSPEITO | MONITORAMENTO |
| evt-iso-005 | 5 | LIMPO | MONITORAMENTO |

---

## Como testar

```bash
docker compose up --build
# Importar workflows/siarc_julho_isolamento_resposta_ativa_n8n.json no n8n e ativar

curl -X POST http://localhost:5678/webhook/siarc/host-isolation \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt-iso-001","src_ip":"203.0.113.88","verdict":"EXPLOIT_CRITICO","score":92,"is_zero_day":true}'
```

Resposta esperada: `status: "ISOLADO_SANDBOX"` com playbook e regras simuladas.

```bash
curl -X POST http://localhost:5678/webhook/siarc/host-isolation \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt-iso-003","src_ip":"10.0.0.44","verdict":"EXPLOIT_CONFIRMADO","score":65}'
```

Resposta esperada: `status: "MONITORAMENTO"` (score abaixo de 80, sem zero-day, verdict não é crítico).

---

## Decisões de design

- **Sem código Python novo / sem endpoint na SIARC API.** O workflow decide e simula usando apenas nós nativos do n8n (`IF` + `Set`), a exemplo do padrão já usado em Abril/Maio/Junho. Isso evita qualquer sobreposição com o algoritmo de Cyber Security Score e a API, que são entrega do outro colaborador.
- **Sem persistência em log próprio.** Cogitou-se gravar cada isolamento em `data/isolation_log.jsonl` via nó `Execute Command` do n8n, mas isso injetaria dados do payload (não confiáveis, vindos de rede) direto em um comando de shell — risco de command injection. A trilha de auditoria (Art. 37 LGPD) já existe em `scripts/audit_trail.py`; a persistência do ticket de isolamento deve ser integrada ali pelo colaborador responsável pela API, não duplicada aqui.
- **Contrato de entrada tolerante a `verdict` e `level`** porque os dois motores existentes (risco de Maio, exploit de Junho) usam nomes de campo diferentes para o veredito.

---

## O que ainda não está implementado (honesto)

- Integração real com firewall/EDR (fora do escopo — sandbox apenas, por objetivo do projeto)
- Persistência do ticket de isolamento (depende da trilha de auditoria da API, entrega do colaborador)
- Liberação automática do host ao expirar o TTL (hoje é só metadado informativo; liberação é manual)
- Notificações (e-mail/Slack) para a equipe SOC
- Score unificado (Cyber Security Score) — entrega do outro colaborador
