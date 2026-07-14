#!/usr/bin/env bash
# Testa o workflow n8n de isolamento (Sprint Julho) contra os 5 eventos de exemplo.
# Requer: n8n rodando e workflow siarc_julho_isolamento_resposta_ativa_n8n.json ativo.
set -euo pipefail

URL="${SIARC_N8N_URL:-http://localhost:5678}/webhook/siarc/host-isolation"
EVENTS_FILE="$(dirname "$0")/../data/sample_logs/julho_isolation_events.jsonl"

# event_id:status_esperado (ver tabela em docs/JULHO_IMPLEMENTADO.md)
EXPECTED="evt-iso-001:ISOLADO_SANDBOX evt-iso-002:ISOLADO_SANDBOX evt-iso-003:MONITORAMENTO evt-iso-004:MONITORAMENTO evt-iso-005:MONITORAMENTO"

fail=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    event_id=$(echo "$line" | python3 -c "import json,sys; print(json.load(sys.stdin)['event_id'])")
    expected=$(echo "$EXPECTED" | tr ' ' '\n' | grep "^${event_id}:" | cut -d: -f2)

    got=$(curl -s -X POST "$URL" -H "Content-Type: application/json" -d "$line" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','ERRO'))")

    if [ "$got" = "$expected" ]; then
        echo "PASS  $event_id  esperado=$expected  obtido=$got"
    else
        echo "FAIL  $event_id  esperado=$expected  obtido=$got"
        fail=1
    fi
done < "$EVENTS_FILE"

exit $fail
