# Fluxo de dados pessoais no SIARC

## Fronteira de confiança

Quando o n8n é usado como ponto de entrada, o payload bruto entra **transitoriamente** no n8n e em seguida é enviado à FastAPI. Portanto, n8n e FastAPI fazem parte da mesma fronteira de confiança do protótipo. O artigo não deve afirmar que o n8n nunca vê dados brutos.

```text
Fonte de evento
      |
      v
[n8n webhook, quando usado]  <-- payload bruto transitório
      |
      v
[FastAPI /analyze]
      |
      +--> detecção/máscara LGPD --> sanitized_event
      |
      +--> extração de fatores + score em memória
      |
      +--> resposta ativa simulada
      |
      v
[PostgreSQL audit_entries]
  - event_id
  - ação / resultado
  - score / nível
  - quantidade de PII
  - IP de origem pseudonimizado
  - sem e-mail/CPF/CNPJ/RG/telefone bruto
```

## Alteração desta revisão

O registro de auditoria não recebe mais o `src_ip` bruto. Mesmo durante o teste baseline com o sanitizer desabilitado, o campo utilizado na auditoria passa separadamente pelo mecanismo de pseudonimização.

## O que permanece em memória

O score utiliza propriedades do evento bruto em memória, pois a classificação do IP e os indicadores textuais fazem parte das regras atuais. Esses valores não precisam ser persistidos para que o cálculo seja realizado.

## O que a avaliação comprova

`pii_effectiveness.py` mede detecção e mascaramento em corpus rotulado. `test_privacy_persistence.py` verifica que o IP privado original não aparece na entrada persistida da auditoria. Isso não equivale a uma certificação geral de conformidade com a LGPD nem prova resistência a reidentificação.
