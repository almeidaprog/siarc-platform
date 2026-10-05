# Blueprint do próximo artigo — orientação JISA

O artigo só deve ser fechado após a execução da bateria final. A nova revisão deve ser escrita em torno do que foi efetivamente medido.

## Título de trabalho recomendado

**Empirical Evaluation of a Privacy-Aware Cybersecurity Event Processing Pipeline with Explainable Rule-Based Risk Scoring**

O título evita colocar privacidade/XAI como se fossem o único foco e explicita que a contribuição principal desta rodada é a avaliação empírica do pipeline.

## Perguntas de pesquisa sugeridas

- **RQ1 — Scalability and stability:** como throughput, latência e taxa de erro mudam com aumento de concorrência e repetições?
- **RQ2 — Privacy effectiveness and overhead:** a camada de sanitização detecta/mascara corretamente os padrões suportados e qual é seu custo de execução?
- **RQ3 — Risk-score effectiveness:** o score segue a política operacional prevista e qual desempenho apresenta em uma avaliação externa cega baseada no UNSW-NB15?
- **RQ4 — Persistence bottleneck:** qual parcela do tempo interno é atribuída à persistência PostgreSQL e como ela evolui sob concorrência?

## Novidade que deve ser demonstrada, não apenas afirmada

1. Governança de PII integrada ao pipeline de eventos de segurança.
2. Score determinístico com explicação intrínseca por fatores.
3. Auditoria SQL rastreável e resposta simulada separada de contenção real.
4. Avaliação conjunta de eficácia da sanitização, comportamento do score, custo de privacidade, persistência e escalabilidade.

## Estrutura recomendada

1. Introduction
2. Related Work
3. SIARC Architecture and Privacy Data Flow
4. Rule-Based Risk Model
5. Experimental Design
6. PII Sanitization Effectiveness
7. Risk-Score Effectiveness
8. Scalability and PostgreSQL Results
9. Discussion
10. Threats to Validity
11. Conclusion

## Regra científica

Nenhum número de desempenho, acurácia ou eficácia deve ser colocado no artigo antes de aparecer nos arquivos produzidos pelos testes finais. Os resultados negativos, erros e limitações devem ser preservados.
