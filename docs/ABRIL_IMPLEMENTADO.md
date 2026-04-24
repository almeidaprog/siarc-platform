# SIARC — Entrega Técnica de Abril/2026

## O que foi implementado

Esta entrega cobre a etapa prevista para abril: revisão bibliográfica sobre XAI e malwares mutáveis, mais configuração do ambiente n8n em sandbox.

## Componentes entregues

1. Ambiente Docker com n8n em sandbox local.
2. API SIARC local para higienização de eventos e cálculo preliminar de risco.
3. Workflow n8n importável para ingestão de eventos de segurança.
4. Script Python de tratamento de logs com mascaramento de dados pessoais.
5. Base de logs simulados para teste.
6. Documentação técnica e revisão bibliográfica preliminar.

## Como executar

```bash
cp .env.example .env
docker compose up --build
```

Acesse o n8n em:

```text
http://localhost:5678
```

API SIARC:

```text
http://localhost:8080/health
```

## Como importar o workflow no n8n

1. Abrir o n8n em `http://localhost:5678`.
2. Criar usuário local.
3. Ir em **Workflows > Import from File**.
4. Importar `workflows/siarc_abril_ingestao_governanca_n8n.json`.
5. Ativar o workflow.

## Teste por cURL

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp":"2026-04-11T02:03:59-03:00",
    "src_ip":"172.16.1.77",
    "dst_ip":"10.0.0.9",
    "event_type":"exploit_attempt",
    "severity":"critical",
    "payload":"CVE-like exploit pattern, privilege escalation attempt",
    "extra":{"email":"teste@example.com","cpf":"123.456.789-00"}
  }'
```

## Resultado esperado

A resposta deve retornar:

- dados pessoais mascarados;
- status `LGPD_SANITIZED`;
- score preliminar de segurança de 0 a 100;
- explicação inicial do cálculo, preparando a camada XAI.

## Limite honesto da entrega

Esta é a etapa de abril: ambiente, ingestão, governança inicial e score preliminar. Ainda não é o SIARC completo. Detecção real de malware, isolamento automático de hosts, dashboard final e testes com exploits ficam para os meses seguintes do cronograma.
