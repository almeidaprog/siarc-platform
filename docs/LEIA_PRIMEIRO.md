# Como testar a entrega de julho

1. Copie `.env.example` para `.env`.
2. Execute `docker compose up --build`.
3. Abra `http://localhost:8080/docs` para testar a API.
4. Também é possível importar a coleção `postman/SIARC_Julho_2026.postman_collection.json` no Postman.
5. Para executar os testes locais, rode `python tests/test_julho.py` a partir da raiz do projeto.

O isolamento de host é simulado. O sistema apenas retorna qual ação seria tomada em um ambiente real.
