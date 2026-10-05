# SIARC — testes finais para a revisão científica

Este pacote foi preparado para responder exatamente aos pontos da nova revisão: eficácia da sanitização e do score, repetição de carga em mais níveis de concorrência, caracterização de hardware/ambiente, confirmação do PostgreSQL, investigação detalhada de erros e documentação do fluxo de dados pessoais.

## Antes de rodar

1. Instale/abra **Docker Desktop**.
2. Tenha **Python 3.12+** instalado.
3. Na raiz do projeto, crie `.env` a partir de `.env.example`.
4. Para reproduzir os scripts sem editar nada, mantenha:

```env
SIARC_API_KEY=siarc-benchmark-key
```

5. Para os testes UNSW-NB15, coloque os arquivos oficiais na pasta `data/` com estes nomes:

```text
data/UNSW_NB15_training-set.csv
data/UNSW_NB15_testing-set.csv
```

Se os datasets ainda não estiverem disponíveis, os testes restantes podem ser executados normalmente; o script indicará quais etapas foram puladas.

## Jeito mais simples

No Windows, execute:

```text
RUN_JISA_TESTS_WINDOWS.bat
```

O script instala as dependências, sobe Docker/PostgreSQL/n8n/FastAPI e roda a bateria completa.

**Tempo esperado:** aproximadamente 30–45 minutos, dependendo do computador.

## O que será executado

1. `pytest` — regressão e propriedades básicas.
2. `pii_effectiveness.py` — precisão, recall, F1 e vazamento da sanitização em corpus sintético rotulado.
3. `score_policy_validation.py` — aderência do score à política de risco e monotonicidade.
4. `verify_postgres.py` — prova pela própria API de que os eventos estão sendo persistidos em PostgreSQL.
5. `run_locust_matrix.py` — 1, 5, 10, 25, 50, 100, 150 e 200 usuários, **3 repetições por nível**.
6. `summarize_locust_matrix.py` — média, desvio-padrão e IC95% por nível.
7. `run_privacy_overhead_docker.py` — sanitizer OFF x ON, 3 repetições, usando Docker/PostgreSQL.
8. `score_unsw_blind_validation.py` — eficácia externa do score no UNSW-NB15 sem usar `label`/`attack_cat` para formar a entrada.
9. `replay_unsw_nb15_http.py` — replay real via HTTP contra Docker/PostgreSQL e arquivo com **cada erro individual**.
10. `collect_environment.py` — CPU, RAM, SO, Python, Docker, Compose e containers.
11. `generate_jisa_figures.py` — gráficos a partir dos resultados finais.
12. `pack_jisa_results.py` — gera um ZIP único para enviar aos autores.

## O que enviar de volta

Quando terminar, envie apenas:

```text
results/SIARC_JISA_RESULTS_<data>.zip
```

Se o `.bat` parar com erro, envie também uma captura do terminal no ponto da falha.

## Prints que ainda valem a pena

Os CSV/JSON são a evidência principal. Prints são complementares. Tire somente:

- `docker compose ps` com API/PostgreSQL/n8n ativos;
- Locust rodando;
- n8n aberto (http://localhost:5678);
- terminal no final dos testes (tela de "CONCLUIDO").

Não é necessário fotografar cada teste: os arquivos gerados são melhores para o artigo.
