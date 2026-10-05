# Protocolo experimental — SIARC/JISA

## Controle do ambiente

Antes da bateria final:

- reiniciar o computador se possível;
- manter o equipamento conectado à energia;
- fechar jogos, IDEs pesadas, sincronizadores e downloads;
- não alterar Docker/PostgreSQL entre os níveis da matriz;
- registrar hardware e software com `collect_environment.py`;
- usar o mesmo commit do código durante toda a bateria.

## Matriz de carga

Níveis: **1, 5, 10, 25, 50, 100, 150 e 200 usuários concorrentes**.

Cada nível é executado **3 vezes**. A ordem dos níveis é embaralhada de forma determinística dentro de cada repetição para reduzir viés térmico/temporal. Há warm-up inicial e pequeno cooldown entre execuções. O resumo apresenta média, desvio-padrão e intervalo de confiança de 95%.

Métricas externas:

- requests/s;
- média, mediana, P95, P99 e máximo de latência;
- número e taxa de falhas.

Métricas internas:

- `t_san_ms`;
- `t_score_ms`;
- `t_db_ms`;
- `t_total_ms`.

## Sanitização

A eficácia é medida em corpus sintético rotulado com casos positivos, negativos, mistos e aninhados. As métricas são precision, recall e F1 por tipo de PII, taxa de falso positivo em controles negativos e taxa de vazamento do valor bruto após sanitização.

A comparação de overhead é executada separadamente com sanitizer OFF/ON, mesmo workload, mesma concorrência e três repetições por condição.

## Score

São usados dois níveis de validação:

1. **Policy conformance:** cenários explícitos de baixo/médio/alto/crítico e teste de monotonicidade.
2. **UNSW-NB15 blind proxy:** a função que constrói o evento não lê `label` ou `attack_cat`; esses campos são usados apenas depois da pontuação para calcular precision, recall, specificity, F1, balanced accuracy e ROC-AUC do score binarizado.

O segundo experimento não transforma o SIARC em modelo de ML e não deve ser descrito como treinamento.

## PostgreSQL

`verify_postgres.py` obtém o backend e a versão do banco pela API, registra a contagem de auditoria, envia eventos controlados e confirma o aumento exato da contagem. A matriz de carga mede `t_db` ao redor do commit de auditoria.

## Erros do replay

O replay via HTTP registra cada falha em `unsw_http_errors.csv`, com índice da linha, tipo (`http` ou `exception`), status e mensagem. Isso permite explicar erros em vez de publicar somente uma contagem agregada.
