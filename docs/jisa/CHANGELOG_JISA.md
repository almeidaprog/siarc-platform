# Alterações desta revisão

- Sanitizador: validação de dígitos verificadores para CPF/CNPJ, validação de IP privado, telefone com regra de formato e varredura que preserva contagem de ocorrências.
- Sanitização recursiva em listas contendo objetos/listas aninhadas.
- Privacidade: IP privado bruto removido das explicações XAI, resposta ativa e auditoria; usa identificador pseudonimizado.
- PostgreSQL: endpoint protegido `/diagnostics/database` com backend, versão, contagem de auditoria e estado do pool sem expor credenciais.
- Métricas: identificação por `run_id` para separar repetições experimentais.
- Sanitização: corpus rotulado de 125 casos e métricas precision/recall/F1/leakage.
- Score: validação de política e validação externa cega opcional com UNSW-NB15.
- Carga: 8 níveis de concorrência, 3 repetições, ordem randomizada, warm-up, cooldown, média/DP/IC95%.
- PostgreSQL: script que comprova persistência pela contagem antes/depois sem exigir `psql`.
- UNSW: replay via HTTP real com CSV detalhando cada erro.
- Reprodutibilidade: captura automática de hardware/software e geração de gráficos.
- Entrega: script único de Windows e empacotamento dos resultados finais.
