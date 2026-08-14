# Evidências Quantitativas — SIARC / ACDSA 2027

Material suplementar gerado a partir da execução real do ambiente (Docker: PostgreSQL + n8n + FastAPI), em `2026-08-14`. Cobre os 12 itens de `prints.md`. Itens 3, 4 e 5 dependem do console web do n8n e foram confirmados via webhook (payload de resposta abaixo); a captura visual do canvas fica a cargo do time.

---

## 1. Docker rodando

```
$ docker compose ps
NAME                IMAGE                      SERVICE     STATUS                    PORTS
siarc-api-sandbox   siarc-platform-siarc-api   siarc-api   Up (healthy)              0.0.0.0:8080->8080/tcp
siarc-n8n-sandbox   n8nio/n8n:latest           n8n         Up                        0.0.0.0:5678->5678/tcp
siarc-postgres      postgres:16-alpine         postgres    Up (healthy)              5432/tcp
```

## 2. API funcionando

```
$ curl http://127.0.0.1:8080/health
{"status":"ok","service":"siarc-api","version":"0.4.0"}
```

Documentação interativa disponível em `http://localhost:8080/docs`.

## 3. n8n com o workflow do SIARC aberto

Workflow `SIARC Julho - Resposta Ativa (Simulação de Isolamento de Host)` importado e ativo em `http://localhost:5678`, com os dois ramos: `Simular Isolamento de Host (Playbook)` e `Não Isolar — Manter Monitoramento`.

> Captura visual do canvas pendente (requer navegador).

## 4. Execução de evento crítico (isolamento)

Disparado via webhook de produção do n8n (`POST /webhook/siarc/host-isolation`) com o evento de exemplo `evt-iso-001` (score 92, zero-day):

```json
{
  "isolation_id": "ISO-1786717151156-465555",
  "host": "203.0.113.88",
  "event_id": "evt-iso-001",
  "status": "ISOLADO_SANDBOX",
  "simulated": true,
  "isolated_at": "2026-08-14T11:19:11.169-03:00",
  "ttl_hours": 4,
  "expires_at": "2026-08-14T15:19:11.172-03:00",
  "requires_human_review": true,
  "firewall_rules_simulated": [
    "DROP ALL FROM 203.0.113.88",
    "DROP ALL TO 203.0.113.88",
    "ALLOW mgmt-gateway <-> 203.0.113.88"
  ],
  "playbook": [
    "1. Bloquear host 203.0.113.88 no firewall perimetral (DROP ALL INBOUND/OUTBOUND)",
    "2. Permitir apenas trafego do gateway de gestao do SOC (allowlist)",
    "3. Revogar sessoes e tokens ativos associados ao host",
    "4. Disparar snapshot de memoria/disco para analise forense",
    "5. Notificar equipe SOC e abrir ticket de resposta a incidente",
    "6. Reavaliacao humana obrigatoria em ate 4h (expira em 2026-08-14T15:19:11.183-03:00)"
  ],
  "xai_explanation": [
    "[DECISAO] score=92 verdict=EXPLOIT_CRITICO zero_day=true atingiu o limiar de resposta ativa (score>=80 OU verdict/level critico OU zero-day)",
    "[ACAO] Isolamento SIMULADO em ambiente de sandbox — nenhuma alteracao real de rede/firewall foi executada",
    "[REVISAO] Isolamento valido por 4h, sujeito a revisao humana antes de liberacao ou escalonamento para incidente"
  ]
}
```

## 5. Execução de evento não crítico (monitoramento)

Evento de exemplo `evt-iso-005` (score 5, verdict `LIMPO`):

```json
{
  "host": "10.0.0.9",
  "event_id": "evt-iso-005",
  "status": "MONITORAMENTO",
  "simulated": true,
  "xai_explanation": [
    "[DECISAO] score=5 verdict=LIMPO abaixo do limiar de isolamento",
    "[ACAO] Nenhum isolamento acionado — evento permanece em monitoramento padrão"
  ]
}
```

## 6. Resposta JSON da API com as métricas

`POST /analyze` (evento crítico com PII no payload):

```json
{
  "event_id": "e3b39753-cb46-42c0-b60f-d0a789d0683b",
  "score": 100,
  "risk_level": "CRÍTICO",
  "performance": {
    "t_san_ms": 0.1223,
    "t_score_ms": 0.0468,
    "t_db_ms": 78.6351,
    "t_total_ms": 78.8842,
    "sanitizer_enabled": true
  }
}
```

`t_db_ms` em regime estável (após warm-up da conexão); primeira chamada após subir o container mostra ~3.4s por causa da criação de tabela/pool, valor descartado como outlier de warm-up.

## 7. Locust — 10 usuários

```
$ python3 -m locust -f experiments/locustfile.py --headless -u 10 -r 5 --run-time 30s -H http://127.0.0.1:8080

Type     Name          # reqs   # fails |   Avg   Min   Max   Med | req/s  failures/s
POST     /analyze         822    0(0%)  |    321    56  1992    97 |  27.90        0.00

Response time percentiles (ms)
50%: 97   66%: 130   75%: 210   90%: 1300   95%: 1400   99%: 2000   100%: 2000
```

822 requisições, 0 falhas, ~28 req/s sustentado.

## 8. Locust — 200 usuários

```
$ python3 -m locust -f experiments/locustfile.py --headless -u 200 -r 20 --run-time 45s -H http://127.0.0.1:8080

Type     Name          # reqs   # fails |   Avg    Min    Max    Med  | req/s  failures/s
POST     /analyze        1473    0(0%)  |   5206    177  10530   5700 |  32.93        0.00

Response time percentiles (ms)
50%: 5700  66%: 6400  75%: 7400  90%: 8800  95%: 9300  99%: 9500  100%: 11000
```

1473 requisições, 0 falhas, latência mediana sobe para 5,7s — demonstra o ponto de saturação sob carga concorrente alta (consistente com a Tabela 1 do plano de revisão ACDSA).

## 9. LGPD ON x OFF (overhead de privacidade)

```
$ python3 experiments/benchmark_local.py --events 300
...
privacy_overhead_pct 2.83
```

| Configuração | Avg Latency (ms) | Overhead |
|---|---|---|
| Sanitizer OFF (baseline) | 156.481 | 0.0% |
| Sanitizer ON (full) | 160.912 | **+2.83%** |

Resultado completo em `results/local_benchmark.json`.

## 10. Replay do UNSW-NB15

```
$ python3 experiments/replay_unsw_nb15.py --rows 1500 --concurrency 20

{
  "dataset": "UNSW-NB15 training partition",
  "rows": 1500,
  "concurrency": 20,
  "duration_s": 28.573,
  "throughput_eps": 52.32,
  "avg_latency_ms": 365.314,
  "p95_latency_ms": 1514.028,
  "errors": 5,
  "error_rate_pct": 0.333,
  "evaluation_scope": "replay stability/throughput only; not detection accuracy"
}
```

Resultado salvo em `results/unsw_replay.json`.

## 11. PostgreSQL recebendo registros

```
$ docker compose exec postgres psql -U siarc -d siarc -c "SELECT count(*) FROM audit_entries;"
 total_eventos
---------------
          2491

$ docker compose exec postgres psql -U siarc -d siarc -c "SELECT event_id, action, outcome, audit_timestamp FROM audit_entries ORDER BY id DESC LIMIT 10;"
               event_id               |              action               | outcome |        audit_timestamp
--------------------------------------+-----------------------------------+---------+-------------------------------
 e5ac9c04-c039-45e8-b869-60883f29456e | FULL_ANALYSIS_AND_ACTIVE_RESPONSE | SUCCESS | 2026-08-13 21:21:45.381953+00
 ceed11ec-652a-444c-ba47-62cbaff7a57a | FULL_ANALYSIS_AND_ACTIVE_RESPONSE | SUCCESS | 2026-08-13 21:21:45.348692+00
 ...
```

2491 registros persistidos de forma append-only na trilha de auditoria (LGPD Art. 37).

## 12. Resultado final do Locust/CSV

```
$ ls -la results/ results/figures/
results/local_benchmark.json
results/local_load.csv
results/locust_10users_stats.csv
results/locust_10users_stats_history.csv
results/locust_10users_failures.csv
results/locust_10users_exceptions.csv
results/locust_200users_stats.csv
results/locust_200users_stats_history.csv
results/locust_200users_failures.csv
results/locust_200users_exceptions.csv
results/unsw_replay.json
results/figures/latency.png
results/figures/stages.png
results/figures/throughput.png
```

---

## Notas técnicas

- Ambiente: Docker Compose local (PostgreSQL 16, n8n `latest` v2.29.10, FastAPI/uvicorn).
- Correção aplicada em `workflows/siarc_julho_isolamento_resposta_ativa_n8n.json`: adicionados os campos `id` (workflow) e `webhookId` (node de webhook), ausentes no export original — sem eles o n8n 2.29.10 não registra o webhook de produção.
- Itens 7–10 usam concorrência via `ThreadPoolExecutor`/Locust; os itens 4–6 usam PostgreSQL real via Docker, enquanto os benchmarks portáteis (9, 10) usam SQLite local para reprodutibilidade fora do Docker (documentado em `results/local_benchmark.json`).
