# SIARC — Entrega de Abril/2026

Base técnica inicial do projeto SIARC: sandbox n8n, ingestão de logs, higienização LGPD e score preliminar de risco.

## Subir ambiente

```bash
cp .env.example .env
docker compose up --build
```

## Serviços

- n8n: http://localhost:5678
- SIARC API: http://localhost:8080/health

## Rodar processamento local sem Docker

```bash
pip install -r requirements.txt
python scripts/log_governance.py
```

## Arquivos principais

- `docker-compose.yml`: sandbox n8n + API local.
- `workflows/siarc_abril_ingestao_governanca_n8n.json`: fluxo importável no n8n.
- `scripts/log_governance.py`: higienização de logs e score preliminar.
- `scripts/siarc_api.py`: endpoint `/analyze` para integração com n8n.
- `docs/ABRIL_IMPLEMENTADO.md`: relatório técnico da entrega.
- `docs/REVISAO_BIBLIOGRAFICA_ABRIL.md`: revisão bibliográfica preliminar.
