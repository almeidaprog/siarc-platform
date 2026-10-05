# Mapa de atendimento à nova revisão

| Comentário recebido | Alteração técnica | Evidência que será gerada |
|---|---|---|
| Alinhar título ao que realmente foi testado | O próximo manuscrito será orientado a avaliação empírica de desempenho/robustez; não será fechado antes dos novos resultados | `docs/jisa/ARTICLE_REVISION_BLUEPRINT.md` |
| Fortalecer trabalhos relacionados e novidade | Separação explícita entre contribuição arquitetural, privacidade, score por regras, orquestração e avaliação experimental | `docs/jisa/ARTICLE_REVISION_BLUEPRINT.md` |
| Validar eficácia da sanitização | Corpus sintético rotulado de 125 casos; métricas por tipo; teste de vazamento; validação CPF/CNPJ e recursão | `results/jisa/pii/*` |
| Validar eficácia do score | Validação de política + experimento cego no UNSW-NB15, sem ground truth na formação da entrada | `results/jisa/score_policy/*`, `results/jisa/score_unsw/*` |
| Repetir testes e ampliar concorrência | 1, 5, 10, 25, 50, 100, 150, 200 usuários; 3 repetições; média/DP/IC95% | `results/jisa/locust_matrix/*` |
| Informar hardware e ambiente | Coleta automática de SO, CPU, RAM, Python, Docker, Compose, containers e commit Git | `results/jisa/environment/*` |
| Medir gargalo PostgreSQL | `t_db` por requisição, confirmação do backend e contagem de auditoria antes/depois | `results/jisa/postgres/*`, matriz Locust |
| Investigar os cinco erros | Replay novo registra row, status HTTP/exception e mensagem de cada falha | `results/jisa/unsw_replay/unsw_http_errors.csv` |
| Esclarecer fluxo de dados pessoais | Fluxo e trust boundary documentados; auditoria não persiste IP bruto | `docs/jisa/DATA_FLOW_PRIVACY.md`, `tests/test_privacy_persistence.py` |
| Adequar à JISA | Estrutura textual proposta para o novo manuscrito após os resultados finais | `docs/jisa/ARTICLE_REVISION_BLUEPRINT.md` |
