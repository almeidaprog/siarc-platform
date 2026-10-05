@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  echo Rode primeiro RUN_JISA_TESTS_WINDOWS.bat ou instale as dependencias.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
echo IMPORTANTE: o workflow workflows\siarc_maio_governanca_lgpd_n8n.json precisa estar IMPORTADO E ATIVO no n8n.
set SIARC_RUN_ID=n8n-e2e-manual
locust -f experiments\locustfile_n8n.py --headless --host http://localhost:5678 -u 25 -r 25 -t 30s --csv results\jisa\n8n_e2e --csv-full-history
pause
