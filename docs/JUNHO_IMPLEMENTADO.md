# SIARC — Entrega Técnica de Junho/2026

**Sprint:** Detecção de Exploits em Tempo Real e Análise de Malwares Mutáveis
**Status:** Concluído
**Relatório Parcial:** 16/06 a 20/06/2026

---

## Objetivo da Sprint

Implementar o módulo de análise especializada de exploits, conforme cronograma do projeto:

> *"Junho/2026: Testes de detecção de exploits em tempo real e envio do Relatório Parcial."*

Capacidades entregues:
- Extração automática de CVEs por regex
- Classificação de 18 categorias de técnicas de exploit
- Mapeamento para MITRE ATT&CK
- Detecção de comportamento polimórfico/metamórfico
- Fingerprinting comportamental por cadeia de ataque
- Correlação temporal com janela deslizante de 300s
- Score de anomalia 0–100 com explicações XAI
- 3 novos endpoints na API REST
- Workflow n8n com roteamento em 4 níveis de criticidade

---

## Componentes entregues

### 1. `scripts/exploit_analyzer.py` — Motor de Análise de Exploits

Módulo central de detecção. Implementa pipeline de 9 etapas:

**Extração de CVEs:**
```
CVE-2024-3094, CVE-2021-44228 → regex CVE-YYYY-NNNNN (case-insensitive)
```

**18 Categorias de técnicas de exploit:**
| Técnica | Peso máx. | MITRE ATT&CK |
|---|---|---|
| zero_day_exploit | 22 pts | T1190 |
| shellcode_injection | 20 pts | T1059 |
| credential_theft | 22 pts | T1003 |
| rop_chain | 20 pts | T1203 |
| remote_code_execution | 18 pts | T1203 |
| privilege_escalation | 18 pts | T1068 |
| memory_corruption | 18 pts | T1203 |
| deserialization_attack | 18 pts | T1190 |
| supply_chain_attack | 18 pts | T1195 |
| polymorphic_malware | 28 pts | T1027 |
| sql_injection | 16 pts | T1190 |
| command_injection | 16 pts | T1059 |
| server_side_request_forgery | 16 pts | T1078 |
| lateral_movement | 16 pts | T1550 |
| data_exfiltration | 16 pts | T1048 |
| xml_external_entity | 16 pts | T1190 |
| buffer_overflow | 14 pts | T1203 |
| path_traversal | 14 pts | T1083 |

**Detecção de comportamento polimórfico:**
Palavras-chave: `polymorphic`, `metamorphic`, `hash mutation`, `self-modifying`, `mutável`, `hash changed`

**Detecção de zero-day:**
- Keywords explícitas: `zero-day`, `0day`, `zeroday`, `undisclosed`
- Heurística: presença de CVE + indícios de exploração ativa

**5 Cadeias de ataque comportamentais:**
| Cadeia | Sequência Detectada | Confiança |
|---|---|---|
| APT_KILL_CHAIN | exploit → privesc → lateral → exfiltração | 95% |
| RANSOMWARE_CHAIN | ransomware_behavior + command_and_control | 92% |
| CREDENTIAL_HARVEST_CHAIN | port_scan + credential_abuse + lateral | 85% |
| RECON_EXPLOIT_CHAIN | port_scan + exploit_attempt | 80% |
| EXFIL_CHAIN | data_exfiltration + command_and_control | 88% |

**Correlação temporal (janela deslizante):**
- Padrão: 300 segundos
- Detecta múltiplos eventos do mesmo IP na janela
- Armazenamento em memória (sandbox) via `deque(maxlen=500)`

**Score e veredito:**
| Score | Veredito | Ação |
|---|---|---|
| 0–24 | LIMPO | Monitorar — sem ação imediata |
| 25–49 | SUSPEITO | Investigar — correlacionar com outros eventos |
| 50–79 | EXPLOIT_CONFIRMADO | Alertar equipe e iniciar análise forense |
| 80–100 | EXPLOIT_CRITICO | Isolamento imediato + plano de resposta a incidente |

---

### 2. API Expandida (v0.3.0) — 3 novos endpoints

#### `POST /analyze/exploit`
Análise individual de um evento com correlação com histórico da janela.

```bash
curl -X POST http://localhost:8080/analyze/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-06-01T03:14:22-03:00",
    "src_ip": "203.0.113.88",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE-2024-3094 xz-utils zero-day exploit; shellcode injection; privilege escalation sudo bypass",
    "window_seconds": 300
  }'
```

**Resposta:**
```json
{
  "event_id": "uuid",
  "exploit_analysis": {
    "exploit_score": 83,
    "verdict": "EXPLOIT_CRITICO",
    "techniques_detected": ["zero_day_exploit", "shellcode_injection", "privilege_escalation"],
    "cves_found": ["CVE-2024-3094"],
    "is_zero_day": true,
    "is_polymorphic": false,
    "mitre_mapping": { "zero_day_exploit": {"tactic": "Initial Access", "technique_id": "T1190"} },
    "xai_explanation": ["[TÉCNICAS] 3 técnica(s)...", "[ZERO-DAY]...", "[SCORE FINAL] 83/100"],
    "recommended_action": "RESPONDER IMEDIATAMENTE — Isolamento imediato..."
  }
}
```

#### `POST /analyze/exploit/batch`
Análise em lote com correlação cruzada entre todos os eventos da lista.

```bash
curl -X POST http://localhost:8080/analyze/exploit/batch \
  -H "Content-Type: application/json" \
  -d '{
    "window_seconds": 300,
    "events": [
      {"event_type": "port_scan", "src_ip": "10.0.0.77", "payload": "scan ports 22,80"},
      {"event_type": "exploit_attempt", "src_ip": "10.0.0.77", "severity": "high",
       "payload": "CVE-2021-44228 Log4Shell exploit; JNDI injection; shellcode delivery"}
    ]
  }'
```

**Vantagem do batch:** o Log4Shell detecta a cadeia RECON_EXPLOIT_CHAIN com o port_scan anterior do mesmo IP.

#### `GET /exploit/history`
Inspeção da janela deslizante de correlação.

```bash
curl "http://localhost:8080/exploit/history?window_seconds=300"
```

---

### 3. `workflows/siarc_junho_exploit_detection_n8n.json` — Workflow n8n Junho

Workflow de 13 nós com roteamento em 4 níveis:

```
Webhook ──► POST /analyze/exploit ──► IF(zero_day?)
                                           ├─ TRUE  ──► Alerta Zero-Day ──────────► Responder
                                           └─ FALSE ──► IF(score≥80?)
                                                             ├─ TRUE  ──► Exploit Crítico ──► Responder
                                                             └─ FALSE ──► IF(score≥50?)
                                                                               ├─ TRUE  ──► Confirmado ──► Responder
                                                                               └─ FALSE ──► Suspeito/Limpo ──► Responder
```

**Endpoint:** `POST http://localhost:5678/webhook/siarc/exploit-detection`

**Prioridades de roteamento:**
| Rota | Prioridade | Ação |
|---|---|---|
| ALERTA_ZERO_DAY | MÁXIMA | Resposta imediata + isolamento |
| EXPLOIT_CRITICO | IMEDIATA | Plano de resposta a incidente |
| EXPLOIT_CONFIRMADO | ALTA | Notificação + análise forense |
| SUSPEITO/LIMPO | NORMAL/BAIXA | Monitoramento contínuo |

---

### 4. `data/sample_logs/junho_exploit_events.jsonl` — Eventos de Teste Junho

10 eventos cobrindo os cenários críticos da sprint:

| Evento | Tipo | Score Esperado | Veredito |
|---|---|---|---|
| CVE-2024-3094 xz-utils zero-day | exploit_attempt | 80+ | EXPLOIT_CRITICO |
| Privilege escalation via CVE-2024-1086 | privilege_escalation | 80+ | EXPLOIT_CRITICO |
| Lateral movement + pass-the-hash | lateral_movement | 50+ | EXPLOIT_CONFIRMADO |
| Polimórfico com hash mutation | suspicious_binary | 25+ | SUSPEITO |
| Port scan interno | port_scan | < 25 | LIMPO |
| Log4Shell CVE-2021-44228 | exploit_attempt | 60+ | EXPLOIT_CONFIRMADO |
| Deserialization (ysoserial) | exploit_attempt | 60+ | EXPLOIT_CONFIRMADO |
| Brute force SSH interno | credential_abuse | 25+ | SUSPEITO |
| SSH → lateral movement chain | lateral_movement | 50+ | EXPLOIT_CONFIRMADO |
| Port scan autorizado | port_scan | < 25 | LIMPO |

---

## Como executar a sprint de Junho

### 1. Subir o ambiente

```bash
cp .env.example .env
docker compose up --build
```

### 2. Testar análise de CVE zero-day

```bash
curl -X POST http://localhost:8080/analyze/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-06-01T03:14:22-03:00",
    "src_ip": "203.0.113.88",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE-2024-3094 xz-utils zero-day exploit; shellcode injection; privilege escalation sudo bypass; remote code execution achieved",
    "window_seconds": 300
  }'
```

### 3. Testar detecção de malware polimórfico

```bash
curl -X POST http://localhost:8080/analyze/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "198.51.100.15",
    "event_type": "suspicious_binary",
    "severity": "high",
    "payload": "polymorphic malware detected: hash mutation on each execution cycle; metamorphic engine; self-modifying code"
  }'
```

### 4. Testar análise em lote (APT Kill Chain)

```bash
curl -X POST http://localhost:8080/analyze/exploit/batch \
  -H "Content-Type: application/json" \
  -d '{
    "window_seconds": 300,
    "events": [
      {"event_type": "exploit_attempt",      "src_ip": "203.0.113.88", "payload": "CVE-2024-3094 shellcode"},
      {"event_type": "privilege_escalation", "src_ip": "203.0.113.88", "payload": "sudo bypass kernel exploit"},
      {"event_type": "lateral_movement",     "src_ip": "203.0.113.88", "payload": "pass the hash credential reuse psexec"},
      {"event_type": "data_exfiltration",    "src_ip": "203.0.113.88", "payload": "dns tunneling exfiltration c2 beacon"}
    ]
  }'
```

**Resultado esperado:** o 4º evento detecta `APT_KILL_CHAIN` com confiança 95%.

### 5. Processar logs de junho em lote

```bash
python3 -c "
from scripts.exploit_analyzer import analyze_exploit, push_to_history
import json, pathlib

events = [json.loads(l) for l in pathlib.Path('data/sample_logs/junho_exploit_events.jsonl').read_text().splitlines() if l.strip()]
for i, event in enumerate(events):
    push_to_history(event)
    profile = analyze_exploit(event, event_history=events[:i])
    print(f'{profile.verdict.value:22} score={profile.exploit_score:3d}  {event[\"event_type\"]}')" 
```

### 6. Inspecionar janela de correlação

```bash
curl "http://localhost:8080/exploit/history?window_seconds=300"
```

### 7. Testar via n8n

```bash
# Importar siarc_junho_exploit_detection_n8n.json e ativar

curl -X POST http://localhost:5678/webhook/siarc/exploit-detection \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-06-01T03:14:22-03:00",
    "src_ip": "203.0.113.88",
    "event_type": "exploit_attempt",
    "severity": "critical",
    "payload": "CVE-2024-3094 zero-day exploit; shellcode injection; privilege escalation"
  }'
```

---

## O que mudou em relação a Maio

| Capacidade | Maio | Junho |
|---|---|---|
| Análise de exploits | keyword matching básico no risk_engine | Módulo dedicado: 18 categorias + MITRE |
| Detecção de CVE | Nenhuma | Regex CVE-YYYY-NNNNN, extração automática |
| MITRE ATT&CK | Mencionado na doc, não implementado | Mapeamento completo por técnica |
| Malware polimórfico | 1 keyword "polymorphic" | 10 keywords + detecção comportamental |
| Zero-day | 1 keyword "zero-day" | Heurística CVE + keywords + peso máximo |
| Correlação temporal | Nenhuma | Janela deslizante 300s (deque in-memory) |
| Cadeias de ataque | Nenhuma | 5 behavioral signatures (APT, ransomware, etc.) |
| Endpoints de exploit | Nenhum | `/analyze/exploit`, `/analyze/exploit/batch`, `/exploit/history` |
| Workflow n8n | 7 nós, 2 rotas | 13 nós, 4 rotas (zero-day + crítico + confirmado + suspeito) |
| Score XAI | Risk score genérico | Exploit score especializado com breakdown por técnica |

---

## Próximas sprints

**Julho/2026 — Algoritmo de Cyber Security Score e Resposta Ativa:**
- Score unificado combinando risk_score (Maio) + exploit_score (Junho)
- Webhook de isolamento de host (integração com firewall via API)
- Playbooks de resposta automática no n8n
- Notificações (email/Slack) para eventos críticos
- Autenticação na API (JWT/OAuth2)

**Agosto/2026 — Baterias de Testes com Vírus Mutáveis:**
- Testes automatizados com corpus de malwares polimórficos simulados
- Métricas de acurácia, recall e F1-score
- Redação do segundo artigo

---

## Limite honesto da entrega

O que **ainda não está implementado**:
- Isolamento automático de hosts comprometidos
- Dashboard de visualização em tempo real
- Integração com SIEM externo (Wazuh, Splunk, Elasticsearch)
- Machine learning real para anomaly detection (atualmente regras + heurísticas)
- Autenticação na API
- Score unificado Cyber Security Score (previsto para Julho)
- A janela deslizante é in-memory: reiniciar o container zera o histórico
