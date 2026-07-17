# Julho/2026 — Cyber Security Score e resposta simulada

Nesta etapa foi concluída a classificação dos eventos por score e adicionada uma resposta automática simulada.

## Faixas usadas

- 0 a 29: BAIXO — monitorar
- 30 a 59: MÉDIO — investigar
- 60 a 79: ALTO — alertar a equipe
- 80 a 100: CRÍTICO — simular isolamento do host

## O que a API retorna

O endpoint `/analyze` agora informa:

- `score`
- `risk_level`
- `recommended_action`
- `active_response`

O isolamento é apenas uma simulação para o ambiente de testes. Nenhuma configuração real do Windows, firewall ou roteador é alterada.

## Teste rápido

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-07-15T03:22:11-03:00",
    "src_ip": "203.0.113.88",
    "dst_ip": "10.0.0.15",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE shellcode privilege escalation zero-day"
  }'
```

Nesse cenário, o resultado esperado é score crítico e ação `ISOLAR_HOST` com status `ISOLAMENTO_SIMULADO`.
