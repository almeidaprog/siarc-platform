# Integração do SIARC em rede real — guia para coleta de casos para o artigo

Este documento descreve como sair do ambiente local (`docker compose up`, dados
sintéticos em `data/sample_logs/`) para um teste monitorado na rede da
instituição, com o objetivo de coletar eventos reais e gerar os *cases* usados
no artigo do projeto.

O SIARC **não é um sensor**: ele não captura tráfego nem escaneia a rede.
Ele é um **serviço de análise que recebe eventos via HTTP** (`/analyze`,
`/analyze/exploit`) e devolve score de risco, veredito de exploit e decisão de
governança LGPD. Para gerar casos reais, algo precisa **observar a rede e
enviar eventos para o SIARC** — essa peça (o "sensor") não existe no projeto
ainda e precisa ser decidida abaixo.

---

## 1. Pré-requisito: autorização formal

Antes de plugar qualquer coisa na rede da instituição:

- **Autorização por escrito** do setor de TI/NTI e do orientador, descrevendo
  escopo (quais segmentos de rede, por quanto tempo), o que será coletado, e
  que o isolamento de host é **simulado** (não há ação de bloqueio real).
- Definir o **período de teste** (ex.: 2–4 semanas) e um **responsável** de
  contato do lado da instituição.
- Se o tráfego capturado puder incluir dados de terceiros (alunos, docentes),
  isso é tratamento de dados pessoais sob a LGPD — trate como pesquisa
  acadêmica com base legal de interesse legítimo/pesquisa (Art. 7º, IX e
  Art. 4º, §4º da Lei 13.709/2018) e minimização de dados, não como "estou só
  testando".
- Combine um **kill switch**: como a instituição pode pedir para você parar
  imediatamente (`docker compose down` no host de monitoramento).

Sem isso, não conecte o sensor à rede — o restante do guia assume que a
autorização já existe.

---

## 2. Onde o SIARC roda e o que ele NÃO faz

- `active_response.py` só retorna um JSON dizendo qual ação *seria* tomada
  (`ISOLAR_HOST`, `ALERTAR_EQUIPE`, ...) — `"simulated": true` sempre. Nenhum
  firewall, switch ou host real é alterado.
- Os workflows n8n (`workflows/*.json`) só reagem a eventos recebidos por
  webhook/HTTP — não fazem varredura ativa da rede.
- Ou seja: o risco técnico de rodar o SIARC na rede é baixo. O risco real está
  em **como os eventos chegam até ele** (o sensor) e em como os dados são
  guardados.

---

## 3. Escolhendo a fonte de eventos reais

Do mais simples para o mais completo. Para um artigo de TCC/ADS, a opção (a)
já é suficiente para gerar casos reais.

### (a) Espelhar logs de um firewall/roteador existente (mais simples)

Se a instituição já tem firewall, IDS ou logs de switch com syslog:

1. Peça ao NTI para exportar/encaminhar os logs (syslog UDP/TCP) para o host
   de monitoramento.
2. Escreva um coletor pequeno (script Python) que lê o syslog e mapeia cada
   linha para o schema esperado pelo SIARC:

   ```python
   # coletor_syslog.py — esqueleto
   import requests, os

   SIARC_URL = "http://localhost:8080/analyze/exploit"
   API_KEY = os.environ["SIARC_API_KEY"]

   def enviar(evento: dict):
       requests.post(
           SIARC_URL,
           json=evento,
           headers={"X-API-Key": API_KEY},
           timeout=5,
       )

   # evento = {
   #   "timestamp": "...", "src_ip": "...", "dst_ip": "...",
   #   "event_type": "port_scan" | "exploit_attempt" | ...,
   #   "severity": "low|medium|high|critical",
   #   "payload": "<trecho relevante do log>",
   # }
   ```

3. Rode o coletor como serviço (`systemd` ou dentro do próprio
   `docker-compose.yml`, novo container).

### (b) Sensor de rede (Suricata/Zeek) num ponto autorizado

Se a instituição liberar uma porta espelhada (SPAN/mirror) de um switch:

1. Suricata em modo IDS (`eve.json` como saída) num host dedicado de
   monitoramento — **nunca** em modo inline/IPS bloqueando tráfego real.
2. Um coletor lê `eve.json` (`tail -F`) e mapeia alertas Suricata para o
   schema `ExploitEvent` (CVE no campo `payload`, categoria em
   `event_type`), enviando para `/analyze/exploit`.
3. Isso gera os casos mais ricos para o artigo (técnicas MITRE ATT&CK,
   detecção de zero-day/polimorfismo do `exploit_analyzer.py`).

### (c) Honeypot leve (ex.: Cowrie) — opcional, para casos de "exploit real"

Um honeypot SSH/Telnet numa VM isolada, exposto deliberadamente, captura
tentativas de exploração reais sem afetar usuários da rede. Bom para gerar
casos de "EXPLOIT_CONFIRMADO"/"zero-day" garantidos para o artigo, mas exige
autorização explícita adicional (é um alvo deliberado na rede da
instituição) e isolamento de rede rígido (a VM não pode enxergar mais nada).

---

## 4. Deploy do SIARC na rede (checklist de segurança)

1. **Host dedicado**, de preferência numa VLAN de laboratório isolada — não
   na mesma rede dos usuários finais.
2. `.env`: gere valores novos (não reaproveite os do repo):
   ```
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # SIARC_API_KEY
   python3 -c "import secrets; print(secrets.token_urlsafe(18))"   # N8N_BASIC_AUTH_PASSWORD
   ```
3. `docker compose up --build -d` — as portas `8080` (API) e `5678` (n8n)
   ficam expostas ao host. Restrinja quem alcança essas portas via firewall
   (`ufw`/`iptables`), liberando só o IP do coletor e o seu próprio IP para
   administração.
4. A API agora exige `X-API-Key` em toda rota exceto `/health` (implementado
   nesta sessão — ver `scripts/siarc_api.py`). Sem isso configurado, o
   servidor responde `503` para qualquer chamada.
5. Coloque um proxy reverso (nginx/Caddy) com TLS na frente se a API for
   acessada fora do host local — mesmo em rede interna, evita trafegar a
   `X-API-Key` em texto puro.
6. Confirme que `data/audit_log.jsonl` (trilha de auditoria) fica só no host
   de monitoramento, sem sincronização automática para nuvem — ele guarda o
   `src_ip` em texto puro nos detalhes de auditoria, então trate esse arquivo
   como dado pessoal (acesso restrito, apagar/anonimizar ao final do teste).

---

## 5. Coletando os casos para o artigo

Com o coletor rodando e alimentando o SIARC, os dados para o artigo saem
diretamente da API — não precisa instrumentar nada extra:

| O que você quer no artigo | Endpoint |
|---|---|
| Casos individuais de exploit (técnicas MITRE, CVEs, veredito) | `GET /audit/entries?limit=100` e `GET /exploit/history` |
| Estatística agregada de conformidade/volume | `GET /governance/report` |
| Cadeias de ataque correlacionadas (kill chain) | `POST /analyze/exploit/batch` reprocessando uma janela de eventos salvos |
| Resumo de auditoria (contagem por ação/outcome) | `GET /audit/summary` |

Sugestão prática: rode um script diário que puxa `/audit/entries` e
`/governance/report` e acrescenta a um `.jsonl` local — isso vira seu dataset
bruto de "casos reais" para as tabelas/gráficos do artigo, sem depender de
manter o ambiente de teste no ar até a data de entrega.

Todos os eventos que passam por `/analyze` já saem com `sanitized_event`
(PII mascarada) e `governance` (decisão LGPD, artigo 6 avaliado) — é esse
campo que deve ir para qualquer anexo público do artigo, nunca o evento cru.

---

## 6. Encerramento do teste

- `docker compose down` no host de monitoramento.
- Exportar/backup de `data/audit_log.jsonl` e `data/processed_events.json`
  para uso no artigo, depois apagar do host (dado pessoal não deve ficar
  residual num ambiente de laboratório compartilhado).
- Avisar o contato da instituição que o teste terminou e o sensor foi
  desligado.
