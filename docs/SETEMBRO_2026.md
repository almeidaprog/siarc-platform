# Setembro/2026 — Refinamento do Dashboard e Produção Bibliográfica Externa

## Marco 1 — Dashboard de Governança

O SIARC v0.5.0 adiciona um painel operacional em `http://localhost:8080/dashboard`.

O dashboard consolida, em uma única tela:

- saúde da API;
- diagnóstico do PostgreSQL e total de registros de auditoria;
- taxa operacional de sucesso das operações registradas;
- latências recentes de sanitização, scoring, persistência e processamento total;
- distribuição das ações de auditoria;
- eventos recentes;
- formulário de análise interativa com Cyber Security Score, nível, explicações XAI intrínsecas, sanitização e resposta ativa simulada;
- snapshot da campanha experimental de setembro/2026 usada no manuscrito destinado à JISA.

### Segurança do dashboard

A página do painel é pública no ambiente local, mas os endpoints operacionais permanecem protegidos por `X-API-Key`. A chave é informada no próprio painel e armazenada apenas no `localStorage` do navegador.

### Como executar

```bash
docker compose up -d --build
```

Depois abra:

- Dashboard: http://localhost:8080/dashboard
- API Docs: http://localhost:8080/docs
- n8n: http://localhost:5678

Use a chave definida em `SIARC_API_KEY` no arquivo `.env`.

## Marco 2 — Produção bibliográfica externa

A campanha experimental de setembro foi consolidada em manuscrito para o *Journal of Information Security and Applications (JISA)*, com foco naquilo que o protótipo efetivamente mede:

- eficácia da sanitização dos padrões de PII suportados;
- conformidade do score baseado em regras com a política operacional definida;
- desempenho do pipeline com PostgreSQL em 8 níveis de concorrência e 3 repetições por nível;
- identificação de persistência síncrona no PostgreSQL como principal gargalo do ambiente testado;
- estabilidade do workflow n8n em teste ponta a ponta.

A submissão externa exige login do autor no sistema editorial da Elsevier e confirmação dos dados autorais/declaratórios no momento do envio.
