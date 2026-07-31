# Como testar a entrega de julho

1. Copie `.env.example` para `.env` e gere uma chave própria para `SIARC_API_KEY`
   (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`) e para
   `N8N_BASIC_AUTH_PASSWORD`.
2. Execute `docker compose up --build`.
3. Abra `http://localhost:8080/docs` para testar a API. Toda rota exceto `/health`
   exige o header `X-API-Key: <valor de SIARC_API_KEY>`.
4. Também é possível importar a coleção `postman/SIARC_Julho_2026.postman_collection.json`
   no Postman — defina a variável de coleção `api_key` com o mesmo valor de `SIARC_API_KEY`.
5. Para executar os testes locais, rode `PYTHONPATH=. python tests/test_julho.py` e
   `PYTHONPATH=. python tests/test_auth.py` a partir da raiz do projeto.

O isolamento de host é simulado. O sistema apenas retorna qual ação seria tomada em um ambiente real.

Para testar em uma rede real (ex.: rede de uma instituição), veja
`docs/INTEGRACAO_REDE_REAL.md` antes de conectar qualquer coisa.
