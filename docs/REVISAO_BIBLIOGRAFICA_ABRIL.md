# Revisão Bibliográfica Preliminar — Abril/2026

## Tema

Inteligência Artificial Explicável (XAI), malwares mutáveis, exploits e governança de dados aplicada à cibersegurança.

## Síntese técnica

A primeira etapa do SIARC exige base conceitual para justificar o uso de IA em ambientes de defesa cibernética. A literatura de segurança aponta que ameaças modernas não dependem apenas de assinaturas estáticas: malwares podem alterar partes do seu comportamento, empacotamento ou hash, dificultando mecanismos tradicionais de detecção.

Nesse cenário, a IA pode auxiliar na identificação de padrões comportamentais. Porém, em segurança cibernética, não basta gerar uma classificação opaca. O gestor precisa compreender por que determinado evento foi considerado crítico. Por isso, a proposta usa XAI como base para produzir explicações mínimas associadas ao score de risco.

A camada de governança é indispensável, porque logs podem conter dados pessoais, como e-mails, identificadores, IPs, nomes de usuário e documentos. Antes da análise, o sistema precisa higienizar ou mascarar dados sensíveis, reduzindo risco jurídico e técnico.

## Eixos estudados

### 1. Malwares mutáveis

Malwares mutáveis alteram características externas ou comportamentais para dificultar identificação. O foco do SIARC não é executar malware real nesta fase, mas sim preparar eventos simulados com indicadores de comportamento suspeito.

### 2. Exploits

Exploits exploram vulnerabilidades de sistemas, serviços ou configurações. Para a etapa inicial, o projeto mapeia eventos como tentativa de escalação de privilégio, varredura de portas e padrões de exploração.

### 3. IA Explicável

A XAI será usada para indicar quais fatores influenciaram o score: severidade do evento, tipo de ameaça, presença de indicadores textuais e criticidade do ativo.

### 4. Governança de Dados

A governança exige tratamento mínimo de logs antes da análise. A entrega de abril implementa mascaramento de CPF e e-mail, além de marcação do evento como sanitizado.

## Referências base do projeto

- ANDERSON, Ross. Security Engineering: A Guide to Building Dependable Distributed Systems. 3. ed. Wiley, 2020.
- BRASIL. Lei Geral de Proteção de Dados Pessoais. Lei nº 13.709/2018.
- TIRONE, Michele et al. Explainable Artificial Intelligence for Cyber Security. Springer, 2022.
- DUTTA, Sourav et al. Zero Trust in Resilient Cloud and Network Architectures. Cisco Press, 2023.
- BOPPANA, S. AI-Native LLM Security. O'Reilly, 2024.
- MOORE, Barclay. AI Data Privacy and Protection. Wiley, 2024.
