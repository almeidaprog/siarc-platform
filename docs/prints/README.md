
# Prints necessários

Tire estes prints, nessa ordem:

1. Docker rodando
   - Terminal mostrando os containers do SIARC ativos: FastAPI, PostgreSQL e n8n (ex.: docker compose ps).
2. API funcionando
   - Navegador ou terminal mostrando a FastAPI respondendo (ex.: /docs ou /health).
3. n8n com o workflow do SIARC aberto
   - Print mostrando o fluxo com os dois ramos: monitoramento e isolamento simulado.
4. Execução de evento crítico no n8n
   - Teste com evento crítico passando pelo ramo de isolamento.
5. Execução de evento não crítico no n8n
   - Teste passando pelo ramo de monitoramento.
6. Resposta JSON da API com as métricas
   - Devem aparecer claramente: t_san_ms, t_score_ms, t_db_ms e t_total_ms.
7. Locust com poucos usuários
   - Print com 10 usuários, mostrando Requests/s, latência e erros.
8. Locust com carga maior
   - Print com 100 ou 200 usuários (importante para demonstrar escalabilidade).
   - Referência: SIARC_ACDSA_2027_Revised_Quanti...
9. Resultado do teste LGPD ON x OFF
   - Terminal ou resultado do benchmark mostrando as duas execuções (sustenta RQ2 sobre overhead da privacidade).
   - Referência: SIARC_ACDSA_2027_Revised_Quanti...
10. Replay do UNSW-NB15
   - Terminal mostrando o script processando o dataset e, ao final: quantidade de eventos; EPS; latência; erros.
11. PostgreSQL recebendo registros
   - Terminal com uma consulta simples na tabela de auditoria mostrando que os eventos foram persistidos.
12. Resultado final do Locust/CSV
   - Se o Locust gerar CSV, print da pasta ou terminal mostrando os arquivos de resultados (preservar como material suplementar).
   - Referência: SIARC_ACDSA_2027_Revised_Quanti...
